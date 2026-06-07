---
slice_id: L.L4
title: Per-control Responsibility Split Renderer
loop: L
status: pending
commit: —
completed_date: —
depends_on: [L.L1, L.L2, LOOP-A.A0 SSP-1/SSP-2 (oscal-ssp + ssp-docx), core/ksi-map.ts]
blocks: [C.C7, F.F1]
estimated_effort: 4-5 working days
last_updated: 2026-06-07
applicable_conditional: false
---

# L.L4 — Per-control Responsibility Split Renderer

## TL;DR
For every Moderate-baseline control, compose a per-control markdown narrative naming the responsibility split (Service Provider / Customer / Shared / Inherited / Not-Applicable) plus FedRAMP's 7-bucket Origination (Service Provider Corporate / Service Provider System Specific / Service Provider Hybrid / Configured by Customer / Provided by Customer / Shared / Inherited from pre-existing Provisional Authorization), and wire those narratives into both (a) OSCAL SSP `control-implementation.implemented-requirements[].responsible-roles[]` + `by-components[]` and (b) the SSP .docx §13 (Control Implementation) section. This is the prose side of the CIS/CRM workbook — what an AO actually reads when reviewing the SSP.

## Status
- Status: pending
- Commit: — (filled when shipped, per `docs/SLICE-COMPLETION-PROCEDURE.md`)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
L.L4 completes LOOP-L's wiring into the OSCAL chain + the .docx SSP renderer. Every narrative composed traces to either L.L1's workbook row (which itself traces to FRMR + KSI + YAML + L.L2), the operator's responsibility-matrix.yaml, or KSI evidence — never fabricated. Specifically:

- **(a) Cloud evidence collection**: not directly consumed, but L.L1's `ksi_ids[]` per row is cited in the narrative ("CSP-implementation status evidenced by: KSI-IAM-MFA") so a 3PAO can trace from the SSP narrative back to the KSI envelope.
- **(b) KSI envelopes**: `ksi-map.ts` consulted for KSI → control mappings; each narrative carries the contributing KSI ids.
- **(c) OSCAL chain (SSP/AP/AR/POA&M)**: L.L4 extends `core/oscal-ssp.ts` to populate `control-implementation.implemented-requirements[].responsible-roles[]` and `by-components[]`. Each by-component carries an `inherited[]` element when the row's responsibility is `'inherited'`, naming the leveraged-authorization UUID from L.L2.
- **(d) FRMR catalog**: indirectly via L.L1 workbook rows (control_id + title + description read verbatim from FRMR via L.L1).
- **(e) SSP .docx**: L.L4 extends `core/ssp-docx.ts` §13 rendering to read per-control markdown narratives instead of the existing placeholder table. The .docx becomes the human-readable representation of every responsibility decision.
- **(f) Tracker DB**: not consumed in first ship; future LOOP-L extension may add a tracker UI for authoring narratives directly.
- **(g) Submission bundle**: per-control narratives bundled as a tarball (`crm-per-control-narratives-tarball`) so the LOOP-A.A4 submission package carries the full SSP §13 source.

## Why this slice exists
The FedRAMP Rev5 SSP Template §13 (Control Implementation) requires, for each control:
- An **Implementation Status** value (Implemented / Partially Implemented / Planned / Alternative Implementation / Not Applicable)
- A **Control Origination** value (the 7-bucket FedRAMP set: Service Provider Corporate / System Specific / Hybrid; Configured by Customer; Provided by Customer; Shared; Inherited from pre-existing Provisional Authorization)
- A **narrative paragraph** describing the implementation

Today, `core/ssp-docx.ts` emits §13 as a placeholder table with empty narratives. The CIS/CRM workbook (L.L1) carries the structured per-control responsibility but does NOT compose the narrative. The OSCAL SSP (`core/oscal-ssp.ts`) emits `control-implementation.implemented-requirements[]` but does NOT populate `responsible-roles[]` or `by-components[]` per control — both are required by FedRAMP's OSCAL conventions when an inherited control points at a leveraged authorization.

L.L4 closes both gaps:

- OSCAL: populates `responsible-roles[]` (role-id mapped to bucket) + `by-components[]` (one entry per touching component: CSO itself + each leveraged authorization with `inherited[]` populated).
- .docx: replaces §13 placeholder with renderer output (per-control table + narrative paragraph).

Per FedRAMP Rev5 SSP Template:

> "Service Provider Corporate / Service Provider System Specific / Service Provider Hybrid / Configured by Customer / Provided by Customer / Shared / Inherited from pre-existing Provisional Authorization"

This is the 7-bucket Origination set L.L4 collapses from L.L1's 5-bucket CIS/CRM set via a documented + tested mapping table.

Per OSCAL SSP v1.1.2 schema:

> "responsible-roles[]: A collection of roles responsible for the implementation."
> "by-components[]: Use of the by-component assembly within this context (component) allows for the documentation of how the specified component satisfies a set of controls."

L.L4 is the only place these schema elements are populated end-to-end.

## Authoritative sources (with verbatim quotes)

- https://www.fedramp.gov/docs/rev5/playbook/csp/ — **FedRAMP Rev5 SSP Template, §13 (Control Implementation)** — 7-bucket Control Origination set verbatim (per template):
  > "[Service Provider Corporate / Service Provider System Specific / Service Provider Hybrid / Configured by Customer / Provided by Customer / Shared / Inherited from pre-existing Provisional Authorization]"
  Implementation Status set verbatim:
  > "[Implemented / Partially Implemented / Planned / Alternative Implementation / Not Applicable]"

- https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/system-security-plan/json-reference/ — **OSCAL SSP v1.1.2** — `control-implementation.implemented-requirements[]`:
  > "Describes how the system satisfies a set of controls."
  Each implemented-requirement carries:
  - `control-id` (required)
  - `responsible-roles[]` — `role-id` + `party-uuids[]`
  - `by-components[]` — `component-uuid` + `description` + `implementation-status` + optionally `inherited[]` (with `leveraged-authorization-uuid` + `description`) + `satisfied[]` + `provided[]`

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev5, §2.5 (Inheritance and Compensating Controls)**:
  > "Inherited controls are documented in the security plan along with the identifier of the providing entity and a description of the inherited control."
  The "description of the inherited control" maps directly to `by-component.inherited[].description` in OSCAL — L.L4's narrative composer fills this.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev5, PL-2 (System Security Plan)**:
  > "Develop security and privacy plans for the system that: … describe the controls in place or planned for meeting the requirements …"
  The "describe the controls" requirement is satisfied by the per-control narrative paragraphs L.L4 composes.

- https://www.fedramp.gov/templates/ — **FedRAMP Rev5 SSP Template (Word document)** — §13 layout: per-control table with columns "Control Number, Control Statement, Implementation Status, Control Origination, Implementation Description". L.L4 + `core/ssp-docx.ts` mirror this layout in the .docx output.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/crm-split-renderer.ts` — pure builder + disk emitter. ~400 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/crm-narrative-template.ts` — pure template-based narrative composer (separation of concerns). ~200 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/crm-split-renderer.test.ts` — integration tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/crm-narrative-template.test.ts` — pure renderer tests (markdown snapshot).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/crm-split/` — fixture workbook + inheritance trace + leveraged-auths + expected per-control narratives.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-ssp.ts` — wire per-control `responsible-roles[]` and `by-components[]` from the renderer index file (`out/crm-per-control-narratives-index.json`). Read once; iterate `implemented-requirements[]`; attach.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/ssp-docx.ts` — replace the §13 "Implementation Status / Control Origination" placeholder table with renderer output (one row per control, columns Control ID / Origination / Status / Narrative). Read narratives from `out/crm-per-control-narratives/<control-id>.md`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--crm-narratives` flag + env `CLOUD_EVIDENCE_CRM_NARRATIVES`. Runs AFTER `--crm` (L.L1) AND BEFORE `--oscal-ssp` + `--ssp-docx`. Implies `--crm`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — add role `crm-per-control-narratives-tarball` (filename `crm-per-control-narratives.tar.gz`) for the per-control markdown tree. Alternatively use the glob `filename_pattern: 'crm-per-control-narratives/*.md'` (matches L.L2's pattern for components/).

## Schemas / standards
- **OSCAL SSP v1.1.2 `responsible-roles[]`** — array per implemented-requirement:
  ```json
  {
    "role-id": "provider" | "customer" | "shared-csp-customer" | "inherited",
    "party-uuids": ["uuid-of-csp" or "uuid-of-leveraged-auth-party"]
  }
  ```
- **OSCAL SSP v1.1.2 `by-components[]`** — array per implemented-requirement. Per FedRAMP convention, one entry for the CSO itself (component-uuid = SSP's primary component) AND one per leveraged authorization (component-uuid = the leveraged-authorization's component UUID emitted by L.L2). Each by-component carries:
  - `component-uuid` (required)
  - `description` (required)
  - `implementation-status` — `state: 'implemented' | 'partial' | 'planned' | 'alternative' | 'not-applicable'`
  - `inherited[]` — array of `{ uuid: ..., description: ..., 'provided-uuid': ... }` per inherited assertion
  - `satisfied[]` — array of `{ 'responsibility-uuid': ..., description: ... }` (future enhancement; collapsed to `inherited[]` in first cut)
  - `provided[]` — array of `{ uuid: ..., description: ... }` (future enhancement; collapsed in first cut)
- **5-bucket → 7-bucket mapping** (decision table, documented in module docstring + tested):
  | L.L1 bucket | Implementation status | Yaml `customer_supplied` | FedRAMP Origination |
  |---|---|---|---|
  | `service-provider` | `implemented` | — | `service-provider-system-specific` |
  | `service-provider` | `partially-implemented` | — | `service-provider-hybrid` |
  | `service-provider` | (corporate-level control like AT-1, PL-1) | — | `service-provider-corporate` |
  | `customer` | — | `false` (default) | `configured-by-customer` |
  | `customer` | — | `true` | `provided-by-customer` |
  | `shared` | — | — | `shared` |
  | `inherited` | — | — | `inherited-pa` |
  | `not-applicable` | `not-applicable` | — | `not-applicable` (narrative-only; not in the 7-bucket set) |
  The mapping is a typed function `mapToFedrampOrigination()`.

## Build steps (concrete, numbered)

1. Define types in `core/crm-split-renderer.ts`:
   ```ts
   export type FedrampOrigination =
     | 'service-provider-corporate'
     | 'service-provider-system-specific'
     | 'service-provider-hybrid'
     | 'configured-by-customer'
     | 'provided-by-customer'
     | 'shared'
     | 'inherited-pa'
     | 'not-applicable';

   export type OscalRoleId = 'provider' | 'customer' | 'shared-csp-customer' | 'inherited';

   export interface PerControlResponsibleRole {
     role_id: OscalRoleId;
     party_uuids: string[];
   }

   export interface PerControlByComponent {
     component_uuid: string;
     implementation_status: ImplementationStatus;
     description: string;
     inherited?: Array<{
       leveraged_authorization_uuid: string;
       description: string;
     }>;
   }

   export interface PerControlNarrative {
     control_id: string;
     control_title: string;
     origination: FedrampOrigination;
     responsibility_bucket: ResponsibilityBucket;          // from L.L1
     narrative_markdown: string;                            // composed paragraph
     responsible_roles: PerControlResponsibleRole[];
     by_components: PerControlByComponent[];
     ksi_ids: string[];                                     // cited in narrative
     narrative_source: 'composed-from-l1' | 'operator-supplied' | 'REQUIRES-OPERATOR-INPUT';
   }

   export interface PerControlNarrativeIndex {
     metadata: { generated_at, system_id, system_name, impact_tier, cis_crm_format_version: '20x.crm.preview.2026' };
     by_control: Record<string, PerControlNarrative>;       // control_id → narrative
     responsibleRolesByControl: Record<string, PerControlResponsibleRole[]>;
     byComponentsByControl: Record<string, PerControlByComponent[]>;
     provenance: { emitter: 'core/crm-split-renderer.ts'; emittedAt: string; sourceCalls: string[]; signingKeyId?: string };
   }
   ```

2. Pure mapper:
   ```ts
   export function mapToFedrampOrigination(
     bucket: ResponsibilityBucket,
     implementationStatus: ImplementationStatus,
     yamlHints: { customer_supplied?: boolean; corporate_control?: boolean },
   ): FedrampOrigination;
   ```
   Implementation matches the decision table above (tested with one test per mapping rule).

3. Narrative composer (`core/crm-narrative-template.ts`):
   ```ts
   export interface NarrativeContext {
     row: CisCrmRow;
     leveraged: LeveragedAuthorization[];
     inheritedFor: InheritedControl[];                      // entries from inheritance-trace.by_control[control_id]
     systemContext: { csp_name: string; system_name: string };
   }
   export function composeNarrative(ctx: NarrativeContext): string;
   ```
   Template (markdown):
   ```markdown
   ### {control_id} — {control_title}

   **Responsibility**: {bucket} (FedRAMP Origination: {origination})

   **Implementation Status**: {status}

   **CSP Implementation**: {implementation_description}

   **Customer Responsibility**: {customer_responsibility}

   {if inherited:}
   **Inherited From**: {pa_id} — {provider title} ({inheritance_scope})

   This control is inherited from the {provider} authorization (PA-id {pa_id}). {inheritance_description}

   {if responsibility-matrix-yaml source:}
   *(Narrative source: operator-supplied via config/responsibility-matrix.yaml)*

   {if KSI evidence present:}
   *(CSP-implementation status evidenced by: {ksi_ids.join(', ')})*

   {if responsibility = 'not-applicable':}
   **Not Applicable Justification**: {justification}
   ```
   The composer NEVER fabricates text — if a field is `REQUIRES-OPERATOR-INPUT`, the template emits the marker verbatim (visible to AO).

4. Responsible-roles + by-components builder:
   ```ts
   export function buildResponsibleRoles(
     row: CisCrmRow,
     cspPartyUuid: string,
     customerPartyUuid: string,
     leveraged: LeveragedAuthorization[],
   ): PerControlResponsibleRole[];

   export function buildByComponents(
     row: CisCrmRow,
     cspComponentUuid: string,
     inheritedFor: InheritedControl[],
     leveraged: LeveragedAuthorization[],
   ): PerControlByComponent[];
   ```
   Rules:
   - `service-provider` row → `responsible-roles: [{ role_id: 'provider', party_uuids: [cspPartyUuid] }]`; `by-components: [{ component_uuid: cspComponentUuid, implementation_status: row.implementation_status, description: row.implementation_description }]`.
   - `customer` row → `responsible-roles: [{ role_id: 'customer', party_uuids: [customerPartyUuid] }]`; by-components includes a placeholder entry naming the customer.
   - `shared` row → `responsible-roles: [{ role_id: 'shared-csp-customer', party_uuids: [cspPartyUuid, customerPartyUuid] }]`; by-components has 2 entries (CSP portion + customer portion).
   - `inherited` row → `responsible-roles: [{ role_id: 'inherited', party_uuids: [leveraged.party_uuid] }]`; by-components has the leveraged authorization's component_uuid with `inherited[]` populated from `inheritedFor`.
   - `not-applicable` → `responsible-roles: []`; by-components has one entry with `implementation_status: 'not-applicable'` and the justification description.

5. **Disk emitter**:
   ```ts
   export interface CrmSplitRendererOptions {
     outDir: string;
     workbookPath?: string;                  // default: outDir/cis-crm-workbook.json
     inheritanceTracePath?: string;          // default: outDir/inheritance-trace.json
     leveragedAuthsPath?: string;            // default: outDir/leveraged-authorizations.json
     systemContext: { csp_name: string; system_name: string; csp_party_uuid: string; customer_party_uuid: string; csp_component_uuid: string };
   }
   export interface CrmSplitRendererResult {
     narrative_count: number;
     dirPath: string;                       // out/crm-per-control-narratives/
     indexPath: string;                     // out/crm-per-control-narratives-index.json
     filePaths: string[];                    // per-control markdown files
   }
   export async function emitCrmSplitNarratives(opts: CrmSplitRendererOptions): Promise<CrmSplitRendererResult>;
   ```
   Writes one markdown file per control to `out/crm-per-control-narratives/<control-id>.md` (slashed control ids like `AC-2(1)` get sanitised to `AC-2_1.md` with the un-sanitised id inside). Writes index JSON for OSCAL consumers.

6. **SSP integration** (`core/oscal-ssp.ts`):
   ```ts
   const narrativeIndexPath = path.join(outDir, 'crm-per-control-narratives-index.json');
   if (fs.existsSync(narrativeIndexPath)) {
     const index: PerControlNarrativeIndex = JSON.parse(fs.readFileSync(narrativeIndexPath, 'utf-8'));
     for (const ir of ssp['control-implementation']['implemented-requirements']) {
       const roles = index.responsibleRolesByControl[ir['control-id']];
       if (roles && roles.length > 0) {
         ir['responsible-roles'] = roles.map(r => ({ 'role-id': r.role_id, 'party-uuids': r.party_uuids }));
       }
       const byComps = index.byComponentsByControl[ir['control-id']];
       if (byComps && byComps.length > 0) {
         ir['by-components'] = byComps.map(bc => ({
           'component-uuid': bc.component_uuid,
           description: bc.description,
           'implementation-status': { state: bc.implementation_status === 'partially-implemented' ? 'partial' : bc.implementation_status === 'alternative-implementation' ? 'alternative' : bc.implementation_status },
           inherited: bc.inherited?.map(i => ({ uuid: crypto.randomUUID(), description: i.description, links: [{ rel: 'leveraged-authorization', href: `#${i.leveraged_authorization_uuid}` }] })),
         }));
       }
     }
   }
   ```

7. **SSP .docx integration** (`core/ssp-docx.ts`):
   - Replace the existing placeholder §13 control implementation table with renderer output.
   - For each control: render a 4-column row (Control ID / Origination / Status / Narrative) reading narrative from `out/crm-per-control-narratives/<sanitised-control-id>.md`.
   - Preserve existing column widths + heading style from the SSP template.

8. **Orchestrator wiring**: `--crm-narratives` runs AFTER `--crm` (L.L1) AND BEFORE `--oscal-ssp` + `--ssp-docx`. Implies `--crm`. Sequence: collect → inventory → leveraged-auth → inheritance-trace → crm → crm-gap → crm-narratives → ssp → ap → ar → poam → bundle → sign → timestamp.

9. **Bundler integration** — add to `submission-bundle.ts:WELL_KNOWN`:
   ```ts
   { role: 'crm-per-control-narratives-tarball', filename: 'crm-per-control-narratives.tar.gz', description: 'Per-control responsibility narratives tarball (LOOP-L.L4)', required: false },
   { role: 'crm-per-control-narratives-index', filename: 'crm-per-control-narratives-index.json', description: 'Per-control narrative index (LOOP-L.L4)', required: false },
   ```
   Tarball composition is handled by the bundler (existing pattern from `ksi-evidence-tarball`).

10. **Provenance** — `crm-per-control-narratives-index.json` carries `provenance` block: emitter name, emittedAt, sourceCalls (workbook + inheritance trace + leveraged-auths + per-narrative-file count), `signingKeyId` filled by `core/sign.ts`.

11. **REQUIRES-OPERATOR-INPUT handling**: if a workbook row has `responsibility_source === 'REQUIRES-OPERATOR-INPUT'`, the renderer emits the narrative file with body `REQUIRES-OPERATOR-INPUT: control responsibility undefined; see cis-crm-gap-report.md` and `narrative_source: 'REQUIRES-OPERATOR-INPUT'`. `--strict-crm` will already have aborted by this point; L.L4 never silently fabricates a narrative.

12. **Sign + timestamp** — all narrative files + index file ride existing `core/sign.ts` glob.

## REQUIRES-OPERATOR-INPUT fields

| Field | Source | Behavior when missing |
|---|---|---|
| Per-control narrative content | L.L1 workbook row (composed from yaml / KSI / inheritance) | When row has REQUIRES-OPERATOR-INPUT bucket, narrative file emits the marker verbatim; `--strict-crm` already aborted |
| `customer_supplied` flag (for `customer` → `provided-by-customer` mapping) | yaml `customer_supplied: true` per control | Default `false` → maps to `configured-by-customer` |
| `corporate_control` flag (for `service-provider` → `service-provider-corporate` mapping) | yaml `corporate_control: true` per control | Default `false` → maps to `service-provider-system-specific` |
| `csp_party_uuid` + `customer_party_uuid` + `csp_component_uuid` | OSCAL SSP `metadata.parties[]` + `system-implementation.components[]` (already populated upstream) | Required for L.L4; loader throws with an actionable error if absent |
| Not-applicable justification text | yaml per control under `responsibility: not-applicable` | Required when bucket is `not-applicable`; L.L1 yaml loader enforces |

## Test specifications (≥12 tests)

1. `it('maps service-provider implemented → service-provider-system-specific')` — assert mapping function.
2. `it('maps service-provider partially-implemented → service-provider-hybrid')` — assert mapping.
3. `it('maps service-provider with corporate_control=true → service-provider-corporate')` — assert mapping.
4. `it('maps customer with customer_supplied=true → provided-by-customer')` — assert mapping.
5. `it('maps customer default → configured-by-customer')` — assert mapping.
6. `it('maps shared → shared')` — assert.
7. `it('maps inherited → inherited-pa')` — assert.
8. `it('maps not-applicable → not-applicable with justification narrative paragraph')` — assert narrative contains "Not Applicable Justification".
9. `it('emits one markdown file per control')` — fixture workbook with 10 rows → 10 .md files emitted.
10. `it('sanitises control_id with parens for filesystem path')` — `AC-2(1)` → `AC-2_1.md`; un-sanitised id preserved inside.
11. `it('narrative includes inheritance section when row is inherited')` — assert "Inherited From: F1411040093" substring.
12. `it('narrative cites KSI evidence sources when ksi_ids present on row')` — assert "evidenced by: KSI-IAM-MFA" substring.
13. `it('responsible-roles populated for service-provider rows with provider role-id')` — assert `[{ role_id: 'provider', party_uuids: [cspUuid] }]`.
14. `it('responsible-roles populated for inherited rows with inherited role-id + leveraged-auth party-uuid')` — assert correct leveraged party uuid.
15. `it('responsible-roles populated for shared rows with shared-csp-customer role-id + both party-uuids')` — assert.
16. `it('by-components has 2 entries for shared rows (CSP + customer)')` — assert.
17. `it('by-components has 1 entry with inherited[] populated for inherited rows')` — assert.
18. `it('SSP control-implementation.implemented-requirements[].responsible-roles[] wired from index')` — run extender; assert SSP has roles populated.
19. `it('SSP control-implementation.implemented-requirements[].by-components[] wired from index')` — assert by-components populated.
20. `it('SSP implementation-status state field is mapped correctly')` — `partially-implemented` → `partial`, `alternative-implementation` → `alternative`.
21. `it('SSP .docx §13 table rendered from per-control markdown')` — render docx; parse; assert §13 contains control_id + Origination columns.
22. `it('emits provenance block on per-control-narratives-index.json')` — `check:provenance` passes.
23. `it('REQUIRES-OPERATOR-INPUT narrative emitted when bucket is REQUIRES-OPERATOR-INPUT')` — assert marker visible in file body + `narrative_source: 'REQUIRES-OPERATOR-INPUT'`.
24. `it('bundler well-known catalogue includes crm-per-control-narratives-tarball + index')` — assert table entries.
25. `it('REO no-stubs check: no TODO/FIXME/placeholder tokens in production code')` — runs `npm run lint:no-stubs`.

## REO compliance specific to this slice
- Every narrative composed from real L.L1 / L.L2 / KSI / yaml data; never fabricated. The narrative template is a pure function over the input row; same inputs → same output.
- The bucket-to-Origination mapping is a constant typed table + tested function; no hidden cases.
- OSCAL `responsible-roles[]` populated only when bucket is known; `not-applicable` controls get empty `responsible-roles[]` (OSCAL-legal).
- `by-components[].inherited[]` populated ONLY when bucket is `'inherited'` AND `inheritance-trace.json` has entries for the control; never fabricated.
- The narrative file is markdown (not HTML, not docx) — composable into the .docx renderer; the .docx layer is responsible for typesetting only.
- Provenance block on the index file per REO Rule 2.6 + `scripts/check-provenance.mjs`.
- No `process.env.NODE_ENV === 'test'` branches (REO Rule 1.8); tests inject seams via dependency-injected file readers.
- Signed by existing `core/sign.ts` pipeline; the manifest glob picks up the index + every per-control file + the tarball.
- The `cis_crm_format_version: '20x.crm.preview.2026'` is propagated to the index; same version pin across all four LOOP-L slices.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/crm-split-renderer.test.ts tests/core/crm-narrative-template.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: 5-bucket → 7-bucket collapse loses information** — the FedRAMP 7-bucket set is more granular than the OSCAL/CIS 5-bucket set. Some compressions (e.g. `service-provider` → either `system-specific` or `corporate`) depend on yaml hints (`corporate_control: true`). Mitigation: hints documented + tested; default mapping documented in module docstring + CHANGELOG.
- **Risk 2: OSCAL by-component `inherited[]` schema mandates `provided-uuid`** — current first cut emits `inherited[]` with `description` + `links[]` but not `provided-uuid` (which requires the leveraged provider's published Component Definition to declare a `provided[]` entry with a UUID we reference). Mitigation: first cut documents the gap; future enhancement adds `provided-uuid` correlation when leveraged provider's CD is loaded; OSCAL validator may warn but not fail.
- **Risk 3: SSP .docx §13 table can be large** — at Moderate (≈325 rows), the .docx file size grows; Word may render slowly. Mitigation: pure-JS OOXML composition is efficient; SheetJS-style streaming write; CHANGELOG notes the size.
- **Risk 4: Filesystem path collisions on control_id with parens** — `AC-2(1)` could conflict with `AC-2_1.md` if both exist. Mitigation: enhancement ids are unique by NIST convention; tests pin the sanitisation rule; collision detection throws.
- **Risk 5: Narrative composition is deterministic but updates frequently** — every yaml change re-emits all narratives. Mitigation: composer is fast (microseconds per control); idempotent; signed manifest catches changes; CHANGELOG documents.
- **Risk 6: Multi-cloud inherited control (inherited from both AWS + GCP)** — `by_control[AC-2]` from L.L2 has 2 entries; the narrative must mention both. Mitigation: composer iterates `inheritedFor[]` array; tests fix this case.
- **Risk 7: `responsible-roles` `role-id` vocabulary not FedRAMP-canonical** — L.L4 uses `'provider'` / `'customer'` / `'shared-csp-customer'` / `'inherited'`; FedRAMP may publish a canonical vocabulary. Mitigation: the role-id values are configurable via constants in `core/crm-split-renderer.ts`; future migration is a separate slice (no production code rewrite).
- **Risk 8: SSP .docx pre-existing §13 layout may differ from L.L4's output** — existing renderer in `core/ssp-docx.ts` could use different column widths / cell styles. Mitigation: ship L.L4 with explicit replacement of the §13 block; tests render full .docx and assert §13 contents; CHANGELOG documents the layout change.
- **Risk 9: KSI citation in narrative could be stale if KSI evidence changes mid-run** — narrative captures `ksi_ids[]` at composition time. Mitigation: composer runs after KSI evidence is fixed (orchestrator order); signed snapshot is consistent.

## Open questions
- **Q1**: Should L.L4 emit the narrative tarball, or leave individual .md files in `out/crm-per-control-narratives/`? Recommend: emit both — individual files are easier to diff in PRs; tarball is the bundle artifact for the submission package.
- **Q2**: Does `core/ssp-docx.ts` currently render §13 at all, or does it emit a placeholder? Recommend: read source at build time; if placeholder, replace with renderer output; if real, extend cleanly without breaking existing tests.
- **Q3**: For `not-applicable` rows, does OSCAL `responsible-roles[]` accept an empty array, or must it have at least one entry? Recommend: empty array is OSCAL-legal per schema; verify with ajv before ship.
- **Q4**: Should the narrative include a "Last Updated" timestamp per control? Recommend: yes — composer pulls from `workbook.metadata.generated_at`; reviewer sees the recency.
- **Q5**: For `shared` rows, do `responsible-roles[]` carry one entry with both party-uuids, or two entries (one per party)? Recommend: one entry with `role_id: 'shared-csp-customer'` and both party_uuids in the array; tests pin.
- **Q6**: Should the .docx renderer emit a "Control Origination" column with the 7-bucket label, or with the FedRAMP-printed format ("Service Provider System Specific")? Recommend: printable label; mapping function provides both keys.
- **Q7**: Filesystem-sanitised control_id naming: `AC-2(1)` → `AC-2_1.md` is one option; `AC-2-1.md` is another. Recommend: `AC-2_1.md` because hyphen already appears in the base id; underscore distinguishes the enhancement.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses, per docs/IMPLEMENTATION-LOG-TEMPLATE.md)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥25 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] STATUS.md updated (slice row + Overall section + LOOP-L marked COMPLETE)
- [ ] LOOP-L-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added per LOOP-L-SPEC.md §12 template
- [ ] Commit with slice ID in message ("LOOP-L.L4: Per-control Responsibility Split Renderer")
- [ ] Commit amended with commit hash recorded in STATUS.md + this file + LOOP-L-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-L-SPEC.md` §5 L.L4 + §6 Loop-wide acceptance criteria.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
5. Read `cloud-evidence/docs/slices/L/L.L1.md` — input format (CisCrmWorkbook + per-row `ksi_ids[]`).
6. Read `cloud-evidence/docs/slices/L/L.L2.md` — input format (`inheritance-trace.json` + `leveraged-authorizations.json`).
7. Read `cloud-evidence/core/oscal-ssp.ts` — your extension point for `implemented-requirements[].responsible-roles[]` + `by-components[]`.
8. Read `cloud-evidence/core/ssp-docx.ts` — your extension point for §13 rendering.
9. Read `cloud-evidence/core/submission-bundle.ts:WELL_KNOWN` — add 2 new role entries.
10. Read `cloud-evidence/core/ksi-map.ts` — for KSI → control look-ups in narrative composition.
11. Read `cloud-evidence/docs/loops/LOOP-L-RISKS.md` — live risks register.
12. Read the FedRAMP Rev5 SSP Template §13 layout (operator-downloaded under `docs/sources/`) — confirms 7-bucket Origination labels.
13. Begin implementation; update Implementation log section as you go.

---
