---
slice_id: D.D1
title: Authorization Boundary Diagram (ABD) emitter
loop: D
status: pending
commit: —
completed_date: —
depends_on: [INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S6, REO-0, LOOP-A.A4]
blocks: [D.D2, D.D3, LOOP-C.C9, LOOP-E.E6, LOOP-G.G4, LOOP-F.F4]
estimated_effort: 4–5 days
last_updated: 2026-06-06
---

# D.D1 — Authorization Boundary Diagram (ABD) emitter

## TL;DR
Generates a deterministic Authorization Boundary Diagram (`boundary.puml` +
`boundary.svg` + `boundary.png` + `boundary-diagram-manifest.json`) directly
from `out/inventory.json` plus `fedramp_boundary` tags. Lands the three
shared modules — `plantuml-render.ts`, `svg-to-png.ts`, `diagram-manifest.ts` —
that D.D2 and D.D3 reuse. Closes SSP §9.1 / Appendix M boundary-diagram gap
with byte-stable output that always agrees with the Integrated Inventory
Workbook.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
SSP §9.1 ("Authorization Boundary") and FedRAMP Appendix M ("Diagrams")
both require a current Authorization Boundary Diagram in the
authorization package. Today every CSP / 3PAO draws this diagram by hand
in Visio / Lucidchart / draw.io and the diagram drifts from real
inventory as soon as a resource is added, retired, retagged, or moved
across accounts. The boundary diagram is also the primary visual proof
to a 3PAO that the Integrated Inventory Workbook (IIW) scope matches
reality: the diagram and the workbook must be byte-aligned on every
significant change (SCN, annual review, post-incident).

This slice closes that gap by generating the ABD from `out/inventory.json`
+ `fedramp_boundary=in|out` tags, so the diagram is reproducible from real
evidence and always consistent with the workbook this same orchestrator
just produced. Operator tag-misses are surfaced as `REQUIRES-OPERATOR-INPUT`
markers in the diagram itself (never silently filled with sample data).

The slice also lands the three shared diagram modules
(`plantuml-render.ts`, `svg-to-png.ts`, `diagram-manifest.ts`) that D.D2
and D.D3 will re-use; D.D1 carries the highest LOC budget of the loop
because of this foundation work.

## Authoritative sources (with verbatim quotes)

### S1 — NIST SP 800-53 Rev5 §3.20 SC-7 (Boundary Protection)
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
(Rev5 with patch release 5.1.1, page reference: SC-7 in the System and
Communications Protection family appendix.)
> "Monitor and control communications at the external managed
> interfaces to the system and at key internal managed interfaces
> within the system; implement subnetworks for publicly accessible
> system components that are physically or logically separated from
> internal organizational networks; and connect to external networks
> or systems only through managed interfaces consisting of boundary
> protection devices arranged in accordance with an organizational
> security and privacy architecture."

The ABD is the primary visual artifact a 3PAO uses to verify SC-7
implementation: it shows the boundary itself, every component on each
side, and every managed interface that crosses.

### S2 — NIST SP 800-53 Rev5 §3.15 PL-2 (System Security and Privacy Plans)
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
(Rev5, PL family appendix.)
> "Develop security and privacy plans for the system that ... describe
> the operational environment for the system and relationships with or
> connections to other systems ... [and] provide an overview of the
> security and privacy requirements for the system."

The ABD is named in the FedRAMP SSP template (Section 9.1) as the
required visualisation of the operational environment + connections.

### S3 — NIST SP 800-53 Rev5 §3.5 CA-3 (Information Exchange)
URL: same Rev5 PDF, CA family appendix.
> "Approve and manage the exchange of information between the system
> and other systems using [Assignment: interconnection security
> agreements; information exchange security agreements; memoranda of
> understanding or agreement; service level agreements; user
> agreements; nondisclosure agreements; other types of agreements]."

Every external interconnection rendered crossing the boundary on the
ABD is governed by a CA-3 agreement; the diagram is how a 3PAO traces
the CA-3 evidence to a specific external system.

### S4 — NIST SP 800-37 Rev2 §2.4 (Authorization Boundaries)
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-37r2.pdf`
(Rev2, RMF guide, §2.4 starts on page 12 of the PDF.)
> "The authorization boundary establishes the scope of protection
> for organizational information systems including people, processes,
> and information technologies that are part of the systems supporting
> the organization's missions and business processes."

Cited verbatim in the ABD's title block as the definitional anchor for
"what's inside the boundary".

### S5 — FedRAMP Authorization Boundary Guidance
URL: `https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf`
(FedRAMP-published, ~26 pages; the "Required Elements" section
enumerates the 9 must-have items.)

The implementer MUST download this PDF before shipping and verify the
exact bullet list below against the document's "Required Elements"
section. The 9 items are widely reported in the FedRAMP community of
practice but the verbatim text from the guidance is the source of
truth:
> "The Authorization Boundary Diagram (ABD) must depict every
> information system component that processes, stores, or transmits
> federal information within the boundary; every external system,
> service, or interconnection that crosses the boundary; the data
> flow direction and the type of data crossing each interface; and
> the FedRAMP authorization status of every leveraged service."

(Paraphrased operational requirement; verbatim text to be quoted in
code comments when the implementer downloads + reads the PDF.)

### S6 — PlantUML Component Diagram syntax reference
URL: `https://plantuml.com/component-diagram`
Used for: D.D1 syntax. Key tokens this slice emits:
- `@startuml ... @enduml` document wrappers.
- `title ...` title block (multi-line via `\n`).
- `package "Name" as alias { ... }` for the boundary container.
- `component "Label" as alias` for grouped in-boundary components.
- `cloud "Service" as alias` for external CSP-leveraged services.
- `[Component] --> [Other] : "label"` for crossing edges.
- `note right of alias : "Authorized Moderate"` for status pins.
- `legend right ... end legend` for the legend pane.

### S7 — OSCAL v1.1.2 SSP / SAP / SAR back-matter spec
URL: `https://pages.nist.gov/OSCAL/reference/1.1.2/system-security-plan/json-reference/#/system-security-plan/back-matter/resources`
Diagrams are referenced from OSCAL artifacts via
`back-matter.resources[]` with `rlinks: [{ media-type: "image/svg+xml", href: "./boundary.svg" }]`.
This slice ships the .svg + manifest first; back-matter wiring is a
post-LOOP-D follow-up (documented in LOOP-D-SPEC §6).

### S8 — RFC 3161 (Time-Stamp Protocol)
URL: `https://datatracker.ietf.org/doc/html/rfc3161`
The signed manifest (`out/manifest.json`) timestamps every file in
`outDir`. Adding `.puml` / `.svg` / `.png` / `.diagram-manifest.json`
to the sign-time enumeration is what brings the ABD outputs under the
RFC 3161 timestamp + Ed25519 signature umbrella the rest of the
artifact-set already enjoys.

### S9 — Graphviz DOT language (used internally by PlantUML)
URL: `https://graphviz.org/doc/info/lang.html`
PlantUML renders most layouts via Graphviz. Understanding DOT helps
debug layout-quality issues + lets the pure-TS fallback renderer
emit DOT-equivalent SVG primitives for the same nodes/edges.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/boundary.ts` — pure builder
  (`buildBoundaryPuml`) + disk emitter (`emitBoundaryDiagram`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/plantuml-render.ts` — shared
  PlantUML-source → SVG renderer (pure-TS subset for the shapes this loop
  uses, plus optional `plantuml.jar` fast-path). Used by D.D1/D.D2/D.D3.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/svg-to-png.ts` — shared SVG
  rasteriser. Detects `sharp` defensively; falls back to a pure-TS PNG
  encoder using `core/zip.ts`'s existing CRC32 helper + `node:zlib`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/diagram-manifest.ts` — shared
  provenance writer. Emits `<diagram>-diagram-manifest.json` enumerating
  every node + every edge with `source.assetUniqueId` / `source.edgeKey`,
  plus `synthesized_fields[]` for any computed label.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/boundary.test.ts` —
  ~15 tests (see Test specifications).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/plantuml-render.test.ts` —
  ~6 tests covering the shared subset renderer once.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/svg-to-png.test.ts` —
  ~4 tests smoke-checking SVG → PNG conversion (gated cleanly when
  `sharp` absent).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/diagram-manifest.test.ts` —
  ~5 tests covering the shared manifest writer once.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-boundary-min.json` —
  3-asset minimal fixture for D.D1 unit tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-boundary-multicloud.json` —
  AWS + GCP + Azure fixture with mixed tags + leveraged services.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  add CLI flag `--abd` + env `CLOUD_EVIDENCE_ABD=1`; add
  `--diagram-format=svg|png|both|puml-only` selector + env
  `CLOUD_EVIDENCE_DIAGRAM_FORMAT`. Wire `emitBoundaryDiagram()`
  between `applyDiagramLabelAndComments` (INV-S6) and `signEvidence()`
  so the ABD is covered by the signed manifest. Console line:
  `ABD: in=<n> out=<m> interconnects=<k> input=<missing> [puml svg png]`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`:
  extend `Role` union with `'boundary-diagram-puml'`,
  `'boundary-diagram-svg'`, `'boundary-diagram-png'`,
  `'diagram-manifest'`. Append four `WELL_KNOWN[]` entries (exact
  filenames + descriptions per LOOP-D-SPEC §4 D.D1).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sign.ts`:
  extend the file-enumeration pattern set with `.puml`, `.svg`, `.png`,
  `.diagram-manifest.json`. (Read the existing extension list first;
  add the four new patterns to the allow-list.)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`:
  add `boundary_tag` coverage row to the registry with per-cloud
  source-of-truth strings:
  - `aws: 'Asset tag fedramp_boundary=in|out (operator-supplied)'`
  - `gcp: 'Asset label fedramp_boundary=in|out'`
  - `azure: 'Asset tag fedramp_boundary=in|out'`
  When the run completes with no asset carrying `fedramp_boundary`,
  the row's `fill_rate = 0` AND the orchestrator emits a single
  `requires_operator_input` diagnostic naming the tag scheme.

## Schemas / standards
- **FedRAMP ABD required-elements list** (S5) — 9 must-have items:
  1. System name + system identifier.
  2. Impact level (Low / Moderate / High).
  3. Authorization boundary itself — single enclosing labelled rectangle.
  4. Every in-boundary component grouped by `(provider, assetType)`.
  5. Every external interconnection (leveraged services, agency systems).
  6. Authorization status per leveraged service ("FedRAMP Authorized
     — Moderate" / "Non-FedRAMP" / "CSP-managed shared service").
  7. Data classification overlay on each crossing edge.
  8. Legend pane.
  9. Date stamp + run-id footer.
- **PlantUML component-diagram tokens** (S6): `@startuml`, `title`,
  `package`, `component`, `cloud`, `note`, `legend`, `-->`, `@enduml`.
- **OSCAL back-matter resource spec** (S7): `media-type: image/svg+xml`,
  `rlinks[].href` relative path.
- **JSON manifest schema** (in `diagram-manifest.ts`):
  ```ts
  interface DiagramManifest {
    version: '1.0.0';
    diagram_kind: 'boundary' | 'network' | 'dataflow';
    emitter: 'cloud-evidence/core/diagrams/<file>.ts';
    emitted_at: string;            // ISO 8601 UTC
    run_id: string;
    source_inventory_path: string; // absolute path to inventory.json
    source_inventory_sha256: string;
    nodes: Array<{
      id: string;                  // PlantUML alias
      label: string;
      kind: 'component' | 'cloud' | 'package' | 'database' | 'actor' | 'usecase' | 'frame' | 'node';
      source:
        | { kind: 'inventory'; assetUniqueId: string }
        | { kind: 'operator'; field: string }
        | { kind: 'synthesized'; rule: string };
    }>;
    edges: Array<{
      from: string;
      to: string;
      label?: string;
      source:
        | { kind: 'inventory-edge'; edgeKey: string; from: string; to: string }
        | { kind: 'operator'; field: string }
        | { kind: 'synthesized'; rule: string };
    }>;
    synthesized_fields: string[];     // e.g. 'group-label:aws·ec2 (n=5)'
    requires_operator_input: Array<{
      field: string;                  // e.g. 'fedramp_boundary_tag_missing'
      consumer: string;               // e.g. 'boundary.puml'
      hint: string;                   // e.g. 'tag asset with fedramp_boundary=in|out'
    }>;
    provenance: {
      tool: 'cloud-evidence';
      version: string;
      signing_key_id?: string;
    };
  }
  ```

## Build steps (concrete, numbered)
1. **Interfaces in `core/diagrams/boundary.ts`** (mirror LOOP-D-SPEC §4
   D.D1 verbatim):
   ```ts
   export interface BoundaryDiagramOptions {
     outDir: string;
     systemName?: string;
     systemId?: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
     formats?: Array<'puml' | 'svg' | 'png'>;
     leveragedServices?: Array<{
       name: string;
       status: 'fedramp-authorized' | 'non-fedramp' | 'csp-managed-shared';
     }>;
   }
   export interface BoundaryDiagramResult {
     paths: { puml?: string; svg?: string; png?: string; manifest: string };
     in_boundary_count: number;
     out_boundary_count: number;
     interconnect_count: number;
     requires_operator_input: string[];
     bytes: number;
   }
   ```
2. **Pure builder** `buildBoundaryPuml(snapshot, opts)`:
   - Read `fedramp_boundary` from `asset.tags` case-insensitively;
     accept aliases `fedramp-boundary`, `boundary`.
   - Partition `assets` into `in[]` / `out[]` / `untagged[]`.
   - Group `in[]` by `(provider, assetType)` → one `component` node each
     with `n=<count>` suffix.
   - Group `out[]` by `(provider, assetType)` → one `component` per group
     inside `package "External Systems"`.
   - For each `InventoryEdge` whose endpoints cross groups, emit a
     `--> :"<dataClassification>"` arrow.
   - For each `leveragedServices[]` entry, emit a `cloud "<name>" as <slug>`
     outside the boundary with a `note right` status pin.
   - For each leveraged service that surfaces from an asset tag
     `leveraged_service=<name>:<status>`, emit similarly.
   - Title block: `title <systemName> — Authorization Boundary Diagram\n<impactLevel> · runId=<runId> · generated <ISO-date>`.
   - When `systemName` missing: title carries `REQUIRES-OPERATOR-INPUT (--system-name)`
     and `missing[]` accumulates `'systemName'`.
   - When `untagged[]` length === `assets.length`: top-of-diagram note
     describes the `fedramp_boundary` tag scheme; every asset rendered
     with `note bottom: REQUIRES-OPERATOR-INPUT — tag asset with fedramp_boundary=in|out`.
   - Legend pane bottom-right with the four group symbols.
3. **Disk emitter** `emitBoundaryDiagram(opts)`:
   - Read `out/inventory.json` via reused
     `core/inventory-emit.ts:readPreviousInventory()` pattern; if
     absent throw `MissingInventoryError` naming the orchestrator step
     that should have produced it.
   - Run `buildBoundaryPuml`.
   - Write `<outDir>/boundary.puml` (always).
   - If `formats` includes `svg`: call shared
     `renderPumlToSvg(puml, opts)`.
   - If `formats` includes `png`: call shared
     `svgToPng(svg, { width: 1600 })`.
   - Write `<outDir>/boundary-diagram-manifest.json` enumerating
     every node + edge.
4. **Shared module `core/diagrams/plantuml-render.ts`**:
   - Detect `plantuml.jar` (env → `which plantuml` → `/usr/local/lib/plantuml.jar` →
     `/opt/homebrew/Cellar/plantuml/*/libexec/plantuml.jar`). When found
     invoke `java -jar <jar> -tsvg -pipe < <puml-source> > <svg-out>`.
     Validate stdout begins with `<?xml` or `<svg`.
   - Otherwise: pure-TS subset renderer implementing the grammar
     documented in the file header. Supported shapes: `package`,
     `component`, `cloud`, `node`, `frame`, `database`, `actor`,
     `usecase`, `note`, `legend`, `-->`/`==>`/`-->` labelled arrows,
     `title`.
   - Layout: top-down columnar packing with explicit width/height
     budgeting (no Graphviz dep). Subset documented inline so
     LOOP-D.D2 and LOOP-D.D3 know what they can use.
   - Throws `PlantUMLRenderError` when neither path can render; never
     silently writes an empty SVG.
5. **Shared module `core/diagrams/svg-to-png.ts`**:
   - Detect `sharp` via `require.resolve('sharp')` defensively.
   - Path (a) `sharp(svgBuffer).png().toBuffer()`.
   - Path (b) pure-TS PNG: parse subset SVG (rectangle, line, text,
     path-M/L), rasterise into RGBA buffer, deflate via `node:zlib`,
     wrap PNG chunks using `core/zip.ts`'s CRC32 helper. Path (b) ships
     opt-in via `--diagram-format=svg+png` with a typed warning when
     `sharp` is absent if implementation exceeds timebox.
6. **Shared module `core/diagrams/diagram-manifest.ts`**:
   - `writeDiagramManifest(opts)` accepts the node/edge lists from the
     pure builder + the source inventory path + run id + sha256, and
     writes `<outDir>/<kind>-diagram-manifest.json`.
   - `synthesized_fields[]` accumulates derived labels (e.g.
     `'group-label:aws·ec2 (n=5)'`).
7. **Wire to orchestrator** `core/orchestrator.ts`:
   - Flag `--abd`, env `CLOUD_EVIDENCE_ABD=1`.
   - Selector `--diagram-format=svg|png|both|puml-only`, env
     `CLOUD_EVIDENCE_DIAGRAM_FORMAT`.
   - Order: AFTER `applyDiagramLabelAndComments`, BEFORE
     `signEvidence()` (so the ABD enters the signed manifest).
   - Console log per LOOP-D-SPEC §4.
8. **Submission bundler** `core/submission-bundle.ts`:
   - Extend `Role` union + `WELL_KNOWN[]` per Files-to-extend.
9. **Inventory coverage** `core/inventory-coverage.ts`:
   - Append `boundary_tag` registry row.
   - In the coverage emitter, populate `boundary_tag.fill_rate` from
     `taggedCount / totalAssets`.
10. **Sign-time pattern set** `core/sign.ts`:
    - Add `.puml`, `.svg`, `.png`, `.diagram-manifest.json` to the
      file-extension allow-list. Confirm by tracing a test run: every
      diagram file appears in `out/manifest.json`'s `files[]`.
11. **Validation pass**:
    - Pure-TS subset renderer self-validates SVG well-formedness.
    - `diagram-manifest.json` validated against an in-source ajv schema
      (mirror the OSCAL-validate pattern in `core/oscal-validate.ts`).
12. **Signing+timestamp**: covered automatically once Step 10 lands.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (CLAUDE.md): every field that cannot be auto-derived
emits a `REQUIRES-OPERATOR-INPUT` marker that names the field,
consumer, and where to fix it.

| Field | Source | What happens when missing |
|---|---|---|
| `fedramp_boundary` asset tag | Cloud resource tag (AWS/Azure) or label (GCP); applied via Terraform/Pulumi/Bicep/console; key accepted as `fedramp_boundary`, `fedramp-boundary`, or `boundary` | Top-of-diagram note describes scheme; every asset gets `note bottom: REQUIRES-OPERATOR-INPUT`; `requires_operator_input[]` includes `'fedramp_boundary_tag_missing'`; coverage row `boundary_tag.fill_rate = 0` |
| `systemName` | CLI `--system-name` or env `CLOUD_EVIDENCE_SYSTEM_NAME` or `config.yaml.system.name` | Title block carries `REQUIRES-OPERATOR-INPUT (--system-name)`; `missing[]` += `'systemName'` |
| `systemId` | CLI `--system-id` or env `CLOUD_EVIDENCE_SYSTEM_ID` | Subtitle marker `REQUIRES-OPERATOR-INPUT (--system-id)`; `missing[]` += `'systemId'` |
| `leveragedServices[]` | Either programmatic `BoundaryDiagramOptions.leveragedServices[]` OR asset tag `leveraged_service=<name>:<status>` | When neither is supplied AND inventory contains no obviously-leveraged services (e.g. no S3/Cloud Storage/Azure Blob in `out[]`), a single `note top: REQUIRES-OPERATOR-INPUT — declare leveraged services via --leveraged-service or tag leveraged_service=<name>:<status>` is emitted |
| Data-classification edge labels | `asset.dataClassification` from either endpoint of the `InventoryEdge`; falls back to tag-derived if S6 inventory enrichment applies | Edge label renders `REQUIRES-OPERATOR-INPUT`; `missing[]` += `dataClassification:<from>-><to>` |
| Impact level | CLI `--impact-level=low|moderate|high` or `config.yaml.system.impact_level` | Required parameter to `BoundaryDiagramOptions`; orchestrator surfaces `REQUIRES-OPERATOR-INPUT (--impact-level)` and refuses to emit the ABD until set (impact level is too load-bearing to fall back) |

The slice does NOT use any default that could be confused for real
data (per REO Rule 1 #5 + Rule 4). When every operator field is
missing, the diagram still emits as a structurally complete PUML/SVG
with explicit markers so the operator sees exactly what to fix.

## Test specifications (≥15 tests)
1. `it('emits puml + svg + png + manifest in default mode')` — runs against
   `inventory-boundary-min.json` (3 assets); asserts all 4 files exist
   with `bytes > 0` and the manifest references each by absolute path.
2. `it('groups in-boundary assets by (provider, assetType) with count suffix')` —
   fixture with 5 AWS EC2 + 2 AWS RDS + 3 GCP GCS yields three
   `component` nodes labelled `"aws·ec2 (n=5)"`, `"aws·rds (n=2)"`,
   `"gcp·gcs (n=3)"`.
3. `it('emits REQUIRES-OPERATOR-INPUT banner when no asset has fedramp_boundary tag')` —
   asserts `boundary.puml` contains the literal `REQUIRES-OPERATOR-INPUT`
   and `result.requires_operator_input` includes
   `'fedramp_boundary_tag_missing'`.
4. `it('respects fedramp_boundary=in vs out and renders separate packages')` —
   3 tagged-in + 2 tagged-out yields exactly two `package` blocks named
   `"Authorization Boundary"` and `"External Systems"`.
5. `it('renders leveraged-service cloud nodes outside the boundary with status label')` —
   `opts.leveragedServices=[{name:'Amazon-S3',status:'fedramp-authorized'}]`
   yields `cloud "Amazon-S3" as amazon_s3` + `note right of amazon_s3 : "FedRAMP Authorized"`.
6. `it('marks edges crossing the boundary with data-classification label from asset.dataClassification')` —
   edge between in-asset (dataClassification=`PII`) and out-asset yields
   `[in_alias] --> [out_alias] : "PII"`.
7. `it('emits REQUIRES-OPERATOR-INPUT on a crossing edge when neither endpoint has dataClassification')` —
   `missing[]` includes `'dataClassification:<from>-><to>'` and the
   arrow label literally reads `REQUIRES-OPERATOR-INPUT`.
8. `it('renders title block with systemName + impactLevel + runId + generated timestamp')` —
   asserts the title line matches the exact substring pattern.
9. `it('emits REQUIRES-OPERATOR-INPUT marker in title when systemName missing')`.
10. `it('is deterministic — identical inputs yield byte-identical puml + manifest')` —
    runs twice, sha256-hashes both outputs, asserts equality. (The manifest
    `emitted_at` must be set from the same canonical clock as the first
    run to satisfy this; the builder accepts a clock parameter.)
11. `it('throws MissingInventoryError when out/inventory.json absent')` —
    asserts the typed error names `inventory-emit.ts:emitInventory()` as
    the missing producer step.
12. `it('writes diagram-manifest naming every node + every edge with source.assetUniqueId')` —
    asserts every PUML alias appears in `manifest.nodes[].id` AND
    `manifest.nodes[].source.assetUniqueId` points at a real asset in
    the fixture.
13. `it('honors --diagram-format=puml-only (no svg/png written)')`.
14. `it('omits PNG cleanly when neither sharp nor pure-TS fallback available, with typed warning')` —
    mock `require.resolve` to fail; assert no `boundary.png` written;
    assert a `PngFallbackUnavailableWarning` was logged.
15. `it('coverage-report boundary_tag.fill_rate reflects tag presence')` —
    fixture-1 with 5/5 tagged → 100%; fixture-2 with 0/5 tagged → 0%;
    fixture-3 with 3/5 tagged → 60%.
16. `it('refuses to emit when impactLevel missing')` — asserts a typed
    error names `--impact-level` as required.
17. `it('leveraged-service tag leveraged_service=Amazon-S3:fedramp-authorized derives cloud node')` —
    fixture asset tagged with the leveraged_service key + value yields
    the cloud node + status pin without programmatic
    `leveragedServices[]` being passed.

(Total: 17 tests in `boundary.test.ts`. Plus 6 in
`plantuml-render.test.ts` + 5 in `diagram-manifest.test.ts` + 4 in
`svg-to-png.test.ts` = 32 tests landing in D.D1.)

### Shared-module test sketches
`plantuml-render.test.ts`:
1. Subset renderer emits well-formed SVG (XML well-formed, `<svg>` root
   with `width`, `height`, `xmlns="http://www.w3.org/2000/svg"`).
2. Component shape renders as `<rect>` + `<text>` with the label.
3. Cloud shape renders as `<path>` cloud silhouette.
4. Labelled arrow renders as `<line>` + arrowhead `<polygon>` +
   label `<text>`.
5. `plantuml.jar` fast-path is skipped cleanly when `which java`
   absent (test mocks `child_process.spawnSync` to simulate absence).
6. Throws `PlantUMLRenderError` when given unsupported shape (e.g.
   `participant Alice` — a sequence-diagram token outside the subset).

`diagram-manifest.test.ts`:
1. Manifest is valid JSON + matches the ajv schema.
2. `nodes[]` enumerates every PUML alias in the builder output.
3. `edges[]` enumerates every arrow.
4. `synthesized_fields[]` lists every computed group label.
5. `provenance.tool === 'cloud-evidence'` + signing-key id is recorded
   when sign step has populated it.

`svg-to-png.test.ts`:
1. With `sharp` present → PNG ≥ 1 KB.
2. With `sharp` absent + pure-TS fallback present → PNG ≥ 1 KB.
3. With both absent → warns + does not write PNG.
4. PNG header bytes are `89 50 4E 47 0D 0A 1A 0A`.

## REO compliance specific to this slice
- **Every node** in the rendered PUML traces to `asset.uniqueId` in
  `out/inventory.json` OR to an operator-supplied `leveragedServices[]`
  entry OR to a tag-derived leveraged-service declaration. No
  fabricated nodes.
- **Every edge** traces to an `InventoryEdge` (computed in INV-P3) OR
  to a tag-derived leveraged-service edge OR to an
  operator-declared `flowOverrides[]` entry (D.D3 only). No invented
  arrows.
- **No silent fallback** for missing operator fields — every miss
  surfaces as `REQUIRES-OPERATOR-INPUT` text in the diagram + a
  `manifest.requires_operator_input[]` entry + (where applicable) a
  coverage-row fill-rate drop.
- **Provenance fields populated**: `emitter`, `emitted_at`,
  `source_inventory_path`, `source_inventory_sha256`, `run_id`,
  `signing_key_id` (after sign step), `tool`, `version`.
- **synthesized_fields[]** names every derived label (e.g.
  `'group-label:aws·ec2 (n=5)'`, `'edge-label:PII'`) so a downstream
  consumer can audit what was computed vs collected.
- **Signed by**: existing `core/sign.ts` Ed25519 + RFC 3161 pipeline,
  once `.puml`/`.svg`/`.png`/`.diagram-manifest.json` join the
  extension allow-list.
- **CHANGELOG entry** names the slice + the four module files + the
  exact test count delta + the verification result.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/boundary.test.ts
npm test -- tests/core/diagrams/plantuml-render.test.ts
npm test -- tests/core/diagrams/diagram-manifest.test.ts
npm test -- tests/core/diagrams/svg-to-png.test.ts
npm run lint:no-stubs
npm run check:provenance
npm run check:coverage-regression
npm run check:reo
```

Spot-check live run:
```bash
cd cloud-evidence
node --import tsx core/orchestrator.ts \
  --aws --gcp \
  --inventory \
  --abd \
  --diagram-format=both \
  --system-name="Acme CSO" \
  --impact-level=moderate \
  --out=out/dev
ls out/dev/boundary.{puml,svg,png}
jq '.requires_operator_input' out/dev/boundary-diagram-manifest.json
```

## Known risks / issues
- **Risk R-D1-1 (high)**: PlantUML subset renderer LOC budget. The
  shared `plantuml-render.ts` carries ~600 lines because it must
  render packages, components, clouds, notes, legends, arrows, AND lay
  them out without Graphviz. **Mitigation**: ship the minimum subset
  D.D1 needs first; let D.D2 and D.D3 expand it as their shapes
  appear. Track grammar coverage in a header comment.
- **Risk R-D1-2 (high)**: layout quality. A pure-TS layout engine
  produces less aesthetically pleasing diagrams than Graphviz. 3PAOs
  may complain. **Mitigation**: the title + legend + grouping all
  carry the substantive content; layout aesthetics are secondary to
  determinism. When `plantuml.jar` is available, the fast-path uses
  Graphviz automatically.
- **Risk R-D1-3 (med)**: PNG generation in pure JS is non-trivial.
  **Mitigation**: ship `sharp` opt-in first with a clear warning when
  absent; full pure-TS PNG implementation is a follow-up that the
  spec allows to be omitted if it exceeds timebox.
- **Risk R-D1-4 (med)**: `out/manifest.json` extension allow-list
  change in `core/sign.ts` could destabilise existing signed-artifact
  tests. **Mitigation**: extend the allow-list with the four new
  patterns as a single Edit; verify existing
  `tests/core/sign.test.ts` does not regress.
- **Risk R-D1-5 (low)**: case-insensitive tag-key matching for
  `fedramp_boundary` (`fedramp-boundary`, `boundary`) could
  accidentally match unrelated keys like `boundary_account_id`.
  **Mitigation**: use exact set membership against the three accepted
  keys, not substring match.
- **Risk R-D1-6 (low)**: `leveragedServices[]` programmatic input vs
  tag-derived input can disagree. **Mitigation**: programmatic
  wins; tag-derived entries are merged with programmatic taking
  precedence on `name` collision.
- **Risk R-D1-7 (low)**: a diagram-manifest schema change breaks
  D.D2/D.D3 once they reuse it. **Mitigation**: bump
  `version: '1.0.0'` field on any breaking change; add a test that
  asserts D.D2/D.D3 manifests use the same version.

## Open questions (for implementation session to resolve)
- **Q1**: Should the title-block ISO date be the wall-clock UTC time of
  the run, or should it be pinned to the run-ledger's `runId` timestamp?
  Determinism test (#10) requires a stable clock — propose pinning to
  `runId` timestamp (which the orchestrator already records).
- **Q2**: When `leveragedServices[]` is non-empty AND no asset is tagged
  `leveraged_service=...`, do we still emit the
  `REQUIRES-OPERATOR-INPUT — declare leveraged services` note?
  Probably no — the operator explicitly declared them programmatically.
- **Q3**: How wide should the in-boundary package render? PlantUML
  auto-sizes; the subset renderer needs a fixed budget. Propose
  `width=1400` for the boundary container with vertical packing of
  groups, but verify in a live render before shipping.
- **Q4**: Does the manifest need a SHA-256 of the rendered PUML in
  addition to the source inventory hash? Useful for determinism
  audits. Propose yes (add `puml_sha256` field to manifest).
- **Q5**: When `inventory.json` has `synthesized_fields[]` from INV-S6
  (Diagram Label auto-synth), should the ABD honour those labels or
  re-derive from `(provider, assetType)`? Propose: honour the synth
  labels when present and surface them in the manifest's
  `synthesized_fields[]` with a note pointing back to INV-S6.
- **Q6**: PNG width — 1600 (LOOP-D-SPEC default) or smaller for
  bundler-size budget? Bundler size for an entire submission package
  currently runs ~6 MB; adding ~300 KB × 3 PNGs is fine. Keep 1600.

## Implementation log (running journal — implementing session updates)
This section is filled in DURING implementation. Leave it empty with a
single placeholder line:
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 32 for this slice's new tests:
      17 boundary + 6 plantuml-render + 5 diagram-manifest + 4 svg-to-png)
- [ ] check:reo green (G1 lint:no-stubs + G2 check:coverage-regression +
      G3 check:provenance)
- [ ] STATUS.md updated (D.D1 row + Overall section: last-shipped + next-priority)
- [ ] LOOP-D-SPEC.md §7 status table updated (D.D1 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
      completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (under
      "### Added — LOOP-D.D1: Authorization Boundary Diagram emitter")
- [ ] Commit with slice ID in message
      (`LOOP-D.D1: Authorization Boundary Diagram emitter`)
- [ ] Commit amended with commit hash recorded in STATUS.md +
      this file + LOOP-D-SPEC.md
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context, here's everything
it needs to start:
1. Read `cloud-evidence/CLAUDE.md` (REO standard, auto-loaded).
2. This file gives you: source obligations + files to create + build
   steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-D-SPEC.md` Sections 2
   (Dependencies) + 3 (Authoritative sources) for loop-wide context.
4. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
5. Inspect `cloud-evidence/core/inventory-workbook.ts` for the
   `CloudAsset`, `InventoryEdge`, `InventorySnapshot` interfaces
   (READ ONLY — do not redefine).
6. Inspect `cloud-evidence/core/inventory-emit.ts` for the
   `readPreviousInventory()` pattern this slice reuses.
7. Inspect `cloud-evidence/core/sign.ts` to confirm the file-extension
   allow-list this slice extends.
8. Inspect `cloud-evidence/core/submission-bundle.ts` to confirm the
   `Role` union + `WELL_KNOWN[]` shape this slice extends.
9. Begin implementation; update the **Implementation log** section
   above as you go.

---

(end of D.D1 per-slice file)
