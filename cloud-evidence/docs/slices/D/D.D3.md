---
slice_id: D.D3
title: Data Flow Diagram (DFD) emitter
loop: D
status: pending
commit: —
completed_date: —
depends_on: [INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S6, REO-0, LOOP-A.A4, D.D1, D.D2]
blocks: [LOOP-C.C9, LOOP-E.E6, LOOP-G.G4 (AFR-MAS information-flow diagram), LOOP-F.F4]
estimated_effort: 4 days
last_updated: 2026-06-06
---

# D.D3 — Data Flow Diagram (DFD) emitter

## TL;DR
Generates a deterministic Data Flow Diagram (`dataflow.puml` +
`dataflow.svg` + `dataflow.png` + `dataflow-diagram-manifest.json`)
directly from `out/inventory.json` asset-to-asset edges plus operator-
supplied data-classification + transport metadata. Reuses the three
shared diagram modules from D.D1. Closes SSP §9.3 ("Data Flow") gap,
anchors the AC-4 (Information Flow Enforcement) narrative, and seeds
the LOOP-G.G4 AFR-MAS information-flow diagram with a real,
reproducible, byte-stable source-of-truth.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
SSP §9.3 ("Data Flow") in the FedRAMP Moderate SSP template requires a
diagram showing every asset-to-asset, asset-to-external-entity, and
asset-to-data-store flow with the classification of the data crossing
each flow + the transport (TLS / mTLS / VPN / native-cloud TLS) on each
flow. The DFD is the primary visual companion to:

- **AC-4 Information Flow Enforcement** — the diagram shows what flows
  are approved AND demonstrates that the system enforces the policy at
  every crossing.
- **CA-3 Information Exchange** — every external-entity edge maps to a
  CA-3 agreement.
- **SC-7 Boundary Protection** — flows crossing the trust boundary
  (D.D1's `fedramp_boundary=in/out`) are visually marked with doubled
  arrows.
- **SC-8 Transmission Confidentiality and Integrity** — every flow's
  transport label proves SC-8 implementation at the wire level.
- **SC-13 Cryptographic Protection** — TLS-1.2 vs TLS-1.3 + mTLS labels
  prove which crypto is in use.

Today every CSP draws the DFD in Lucidchart and it drifts the moment a
new RDS instance is added or a Pub/Sub subscription is created. The DFD
is also frequently inconsistent with the boundary diagram (different
asset names, different edges) — generating both from the same
`inventory.json` snapshot eliminates the inconsistency.

D.D3 closes this gap by deriving the DFD from real `InventoryEdge[]`
data (RDS→EC2, S3→Lambda, Pub/Sub→Functions, etc.) and overlaying
operator-supplied `dataClassification` + `transport` metadata, with
explicit `REQUIRES-OPERATOR-INPUT` markers where the data isn't
present.

This slice also produces the `buildDataFlowGraph()` output that
LOOP-G.G4 (AFR-MAS Minimum Assessment Scope) reuses to generate the
information-flow diagram for the AFR family — re-implementing graph
extraction would be a REO violation, so this slice exports the graph
data alongside the rendered diagram.

## Authoritative sources (with verbatim quotes)

### S1 — NIST SP 800-53 Rev5 §3.1 AC-4 (Information Flow Enforcement)
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
(Rev5 with patch release 5.1.1, AC family appendix.)
> "Enforce approved authorizations for controlling the flow of
> information within the system and between connected systems based on
> [Assignment: organization-defined information flow control
> policies]."

The DFD is the visualization of the flow-control policy: every arrow
is an approved flow; every flow's label cites the classification +
transport that the policy specifies.

### S2 — NIST SP 800-53 Rev5 §3.5 CA-3 (Information Exchange)
URL: same Rev5 PDF, CA family appendix.
> "Approve and manage the exchange of information between the system
> and other systems using [Assignment: interconnection security
> agreements; information exchange security agreements; memoranda of
> understanding or agreement; service level agreements; user
> agreements; nondisclosure agreements; other types of agreements]."

Every flow crossing to an external entity on the DFD is governed by a
CA-3 agreement; the diagram is how a 3PAO traces the CA-3 evidence to
a specific external system.

### S3 — NIST SP 800-53 Rev5 §3.20 SC-8 (Transmission Confidentiality and Integrity)
URL: same Rev5 PDF, SC family appendix.
> "Protect the [Selection (one or more): confidentiality; integrity]
> of transmitted information."

Every transport label on the DFD (TLS-1.2 / TLS-1.3 / mTLS / VPN-IPsec)
maps to an SC-8 implementation choice.

### S4 — NIST SP 800-53 Rev5 §3.20 SC-13 (Cryptographic Protection)
URL: same Rev5 PDF, SC family appendix.
> "Determine the [Assignment: organization-defined cryptographic uses]
> and implement the following types of cryptography required for each
> specified cryptographic use: [Assignment: organization-defined types
> of cryptography for each specified cryptographic use]."

The transport-label taxonomy on each flow names a FIPS-validated
cryptographic profile (TLS-1.2-FIPS, TLS-1.3-FIPS, mTLS, native cloud
TLS) so a 3PAO can map each flow to a SC-13 cryptographic-use entry.

### S5 — Yourdon / DeMarco Structured Analysis DFD notation
References: Yourdon, E. "Modern Structured Analysis" (1989); DeMarco,
T. "Structured Analysis and System Specification" (1979).
Classic structured-analysis symbology this slice emits:
- **External entity** = rectangle (also called "terminator"). In PUML,
  rendered as `actor "Agency System" as agency`.
- **Process** = circle (or rounded rectangle). In PUML, rendered as
  `usecase "Process: <name>" as proc1`.
- **Data store** = open rectangle (or `<store_id> Name` between two
  parallel lines). In PUML, rendered as `database "<store-name>" as ds1`.
- **Data flow** = labelled arrow. In PUML, rendered as `agency --> proc1 : "<classification>:<transport>"`.

Note: PlantUML has no canonical DFD diagram type. We use the same
component-diagram subset as D.D1 / D.D2 with `actor` (external entity),
`usecase` (process), `database` (data store), and labelled arrows.
The shared `plantuml-render.ts` subset already supports all four shapes.

### S6 — FedRAMP Authorization Boundary Guidance, Data Flow section
URL: `https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf`
The guidance enumerates DFD required elements: external entities,
in-boundary processes / stores, flows labelled with classification +
direction, trust-boundary lines.

### S7 — NIST SP 800-122 (Guide to Protecting PII)
URL: `https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-122.pdf`
> "Personally Identifiable Information (PII) is any information about
> an individual maintained by an agency, including (1) any information
> that can be used to distinguish or trace an individual's identity
> ... and (2) any other information that is linked or linkable to an
> individual ..."

PII is one of the classification labels on DFD flows. CUI is another.

### S8 — NIST SP 800-171 Rev3 / DOD CUI Registry
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf`
+ `https://www.archives.gov/cui/registry/category-list`
CUI (Controlled Unclassified Information) classification is one of the
high-impact labels on flows. Operator-supplied via tag
`dataClassification=CUI`.

### S9 — FIPS 140-3 (Security Requirements for Cryptographic Modules)
URL: `https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf`
> "FIPS 140-3 specifies the security requirements that will be
> satisfied by a cryptographic module utilized within a security
> system protecting sensitive but unclassified information ..."

Transport labels distinguish FIPS-validated TLS from non-FIPS TLS.
Tag value `fips_validated=true` or `false` overrides the default.

### S10 — RFC 8446 (TLS 1.3) + RFC 5246 (TLS 1.2)
URLs: `https://datatracker.ietf.org/doc/html/rfc8446` /
`https://datatracker.ietf.org/doc/html/rfc5246`
Transport labels reference these RFCs by spec name (TLS-1.2, TLS-1.3).

### S11 — PlantUML actor/usecase/database syntax
URL: `https://plantuml.com/use-case-diagram` (actor + usecase) /
`https://plantuml.com/component-diagram` (database).
All four shapes are in D.D1's shared subset renderer.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/dataflow.ts` —
  pure builder (`buildDataFlowPuml`) + disk emitter
  (`emitDataFlowDiagram`) + exported graph data
  (`buildDataFlowGraph()` returns `{ nodes: DfdNode[], flows: DfdFlow[] }`
  for LOOP-G.G4 reuse).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/dataflow.test.ts` —
  ~15 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-dataflow-min.json` —
  3-asset fixture: EC2 + RDS + S3 with edges + classifications + open
  ports.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-dataflow-multicloud.json` —
  AWS + GCP + Azure fixture with cross-cloud edges + external entities.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  add CLI flag `--dfd` + env `CLOUD_EVIDENCE_DFD=1`. Runs after
  `--network-diagram` (when both flagged). Console log:
  `DFD: entities=<e> processes=<p> stores=<s> flows=<f> classified=<c> unclassified=<u> input-required=<i>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`:
  extend `Role` union with `'dataflow-diagram-puml'`,
  `'dataflow-diagram-svg'`, `'dataflow-diagram-png'`. Append three
  `WELL_KNOWN[]` entries:
  - `{ role: 'dataflow-diagram-puml', filename: 'dataflow.puml', description: 'Data Flow Diagram — PlantUML source' }`
  - `{ role: 'dataflow-diagram-svg', filename: 'dataflow.svg', description: 'Data Flow Diagram — SVG render' }`
  - `{ role: 'dataflow-diagram-png', filename: 'dataflow.png', description: 'Data Flow Diagram — PNG render' }`
  (The `diagram-manifest` role from D.D1 already covers `dataflow-diagram-manifest.json`.)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`:
  add two coverage rows:
  - `data_classification` — per-cloud source-of-truth:
    - `aws: 'Asset tag dataClassification=Public|Internal|CUI|PII|FOUO'`
    - `gcp: 'Asset label dataClassification=Public|Internal|CUI|PII|FOUO'`
    - `azure: 'Asset tag dataClassification=Public|Internal|CUI|PII|FOUO'`
    Populate `fill_rate = taggedAssets / totalAssets`.
  - `data_flow_transport` — operator-supplied via `--flow-overrides`
    file OR per-edge metadata:
    - `aws/gcp/azure: 'Edge attribute transport from flowOverrides[] or asset.tags.transport'`
    Populate `fill_rate = edgesWithTransport / totalEdges`.

## Schemas / standards
- **PlantUML subset shapes used**: `actor`, `usecase`, `database`,
  labelled `-->` + `==>` arrows, `note`, `title`. All in the shared
  subset renderer from D.D1.
- **Data classification taxonomy** (operator-supplied via tags):
  - `Public` — no marking required.
  - `Internal` — organisationally internal; not external-facing.
  - `CUI` — Controlled Unclassified Information per NIST SP 800-171.
    MUST appear on every flow carrying CUI.
  - `PII` — Personally Identifiable Information per NIST SP 800-122.
  - `FOUO` — For Official Use Only.
  - `Other` — operator-named string (preserved verbatim).
  - `UNCLASSIFIED` — synthesized when neither endpoint has tag;
    surfaces as `requires_operator_input[]`.
- **Transport taxonomy** (derived from openPorts + operator metadata):
  - `TLS-1.3` / `TLS-1.2` — derived from `openPorts` 443 (default
    TLS-1.3 unless `tls_version=1.2` tag).
  - `mTLS` — operator-tagged `transport=mtls` or asset is in a
    service mesh (Istio/Linkerd) detected by INV-P3.
  - `VPN-IPsec` / `VPN-WireGuard` — operator-supplied.
  - `RDS-native` / `Cloud-SQL-native` / `Azure-SQL-native` — proxied
    through the cloud's TLS-mandatory DB protocol; default for
    database flows.
  - `In-VPC-private` — both endpoints share `vlanNetworkId`; data is
    in-cloud private.
  - `UNCLASSIFIED` / `REQUIRES-OPERATOR-INPUT-transport` — when
    neither openPorts nor tag yields a value.
- **DFD primitive classification rules** (asset → entity / process / store):
  - **Data store**: `assetType` matches
    `/storage|bucket|s3|gcs|blob|disk|database|sql|dynamodb|firestore|cosmos|table|warehouse|kvs|cache/i`.
  - **Process**: `assetType` matches
    `/instance|compute|vm|function|lambda|cloud-run|cloud-function|container|task|service|aks|gke|eks|app-service/i`.
  - **Infrastructure** (not drawn): everything else (VPC, subnet, route,
    SG, etc. — these are the substrate, not data flow primitives).
- **External entity sources** (operator-supplied):
  - `opts.externalEntities[]` — programmatic, takes precedence.
  - Asset tag `external_entity=<name>:<type>` — derived from
    inventory.
  - When neither: single placeholder `actor "Agency Tenant" REQUIRES-OPERATOR-INPUT`
    with note pointing to the tag scheme + CLI flag.
- **Trust-boundary rendering**: when an asset has `fedramp_boundary=in`
  (D.D1's tag) AND an edge connects it to an `out` asset, the arrow is
  doubled (`==>`) and labelled with the classification + transport.
  This visually distinguishes boundary-crossing flows from intra-
  boundary flows.
- **JSON manifest schema** identical to D.D1's, with
  `diagram_kind: 'dataflow'`. Additional fields:
  - `entity_count`, `process_count`, `store_count`, `flow_count`
  - `classified_flow_count`, `unclassified_flow_count`
  - `transport_fill_rate` (0.0–1.0)
  - `requires_operator_input` entries per missing classification /
    transport / entity.

## Build steps (concrete, numbered)
1. **Interfaces in `core/diagrams/dataflow.ts`** (mirror LOOP-D-SPEC §4
   D.D3):
   ```ts
   export interface DataFlowDiagramOptions {
     outDir: string;
     runId: string;
     externalEntities?: Array<{
       name: string;
       type: 'agency' | 'user-class' | 'external-system';
     }>;
     flowOverrides?: Array<{
       from: string;            // asset.uniqueId
       to: string;              // asset.uniqueId or externalEntities[].name
       classification: string;  // taxonomy value
       transport: string;       // taxonomy value
     }>;
     formats?: Array<'puml' | 'svg' | 'png'>;
   }
   export interface DataFlowDiagramResult {
     paths: { puml?: string; svg?: string; png?: string; manifest: string };
     entity_count: number;
     process_count: number;
     store_count: number;
     flow_count: number;
     classified_flow_count: number;
     unclassified_flow_count: number;
     requires_operator_input: string[];
     bytes: number;
   }
   export interface DfdGraph {
     nodes: Array<{
       id: string;
       kind: 'entity' | 'process' | 'store';
       label: string;
       source:
         | { kind: 'inventory'; assetUniqueId: string }
         | { kind: 'operator'; field: string };
     }>;
     flows: Array<{
       from: string;
       to: string;
       classification: string;
       transport: string;
       crosses_trust_boundary: boolean;
       source:
         | { kind: 'inventory-edge'; edgeKey: string }
         | { kind: 'operator'; field: string };
     }>;
   }
   export function buildDataFlowGraph(
     snapshot: InventorySnapshot,
     opts: DataFlowDiagramOptions
   ): DfdGraph & { missing: string[] };
   ```
2. **Pure builder** `buildDataFlowPuml(snapshot, opts)`:
   - Call `buildDataFlowGraph(snapshot, opts)` to get `nodes` + `flows`
     + `missing[]`. This same function is exported and reused by
     LOOP-G.G4 — DO NOT duplicate the classification logic.
   - Classify each asset into entity / process / store per the rules
     above. "Infrastructure" assets are dropped from the diagram and
     emitted as a `manifest.infrastructure_filtered_count` integer.
   - Emit one `actor` per entity (programmatic or tag-derived).
   - Emit one `usecase` per process. Label
     `"Process: <provider>·<assetType> (<count>)"`.
   - Emit one `database` per store. Label
     `"<store-name>"` (use asset's `name` or `uniqueId`).
   - Emit labelled arrows per `flows[]`. Crossings (where
     `crosses_trust_boundary === true`) use `==>` doubled arrow; all
     others use `-->`.
   - Trust-boundary rendering: when D.D1's `fedramp_boundary` tag is
     populated on every asset, draw a `package "Trust Boundary"`
     around in-boundary nodes and a `package "External"` around
     out-boundary nodes. When tag is missing, emit a single
     `note top` describing the tag scheme + add
     `'trust-boundary-tag-missing'` to missing[].
   - Title: `title Data Flow Diagram\nrunId=<id> · generated <ISO-date>`.
3. **Disk emitter** `emitDataFlowDiagram(opts)`:
   - Read `out/inventory.json` via the same
     `readPreviousInventory()` pattern. If absent throw
     `MissingInventoryError`.
   - Run `buildDataFlowPuml`.
   - Write `<outDir>/dataflow.puml` (always).
   - If `formats` includes `svg`: call shared `renderPumlToSvg`.
   - If `formats` includes `png`: call shared `svgToPng`.
   - Write `<outDir>/dataflow-diagram-manifest.json` enumerating every
     node + every flow + every classification source + every
     transport source.
4. **Wire to orchestrator** `core/orchestrator.ts`:
   - Flag `--dfd`, env `CLOUD_EVIDENCE_DFD=1`.
   - Inherit `--diagram-format` from D.D1.
   - Optional flag `--flow-overrides=<path>` to load a YAML/JSON file
     mapping `from`/`to` pairs to classification + transport. The
     file's schema is documented in the file header of `dataflow.ts`.
   - Optional flag `--external-entities=<path>` to load programmatic
     externalEntities[]. Same precedence rule: programmatic wins, then
     tag-derived.
   - Runs at the same pipeline point as D.D1 / D.D2: after S6
     enrichment, before signing.
5. **Submission bundler** `core/submission-bundle.ts`: extend Role +
   WELL_KNOWN as documented.
6. **Inventory coverage** `core/inventory-coverage.ts`: add the two
   new rows.
7. **Validation pass**: ajv-validate the manifest. Every flow MUST
   carry both `classification` and `transport`; when either is
   `UNCLASSIFIED` or `REQUIRES-OPERATOR-INPUT-transport`, the
   `requires_operator_input[]` array MUST contain a matching entry.
8. **Signing + timestamp**: covered automatically by D.D1's
   `core/sign.ts` allow-list extension.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (CLAUDE.md): every field that cannot be auto-derived
emits a `REQUIRES-OPERATOR-INPUT` marker that names the field,
consumer, and remediation hint.

| Field | Source | What happens when missing |
|---|---|---|
| `dataClassification` asset tag | Cloud resource tag/label; key accepted as `dataClassification`, `data_classification`, or `fedramp_data_classification` | Flow label renders `UNCLASSIFIED:<transport>`; `missing[]` += `dataClassification:<asset.uniqueId>`; coverage row `data_classification.fill_rate` drops |
| `externalEntities[]` | Either `opts.externalEntities[]` programmatic OR asset tag `external_entity=<name>:<type>` | Single placeholder `actor "Agency Tenant" REQUIRES-OPERATOR-INPUT` emitted at top of diagram; `missing[]` += `externalEntities` |
| `transport` for cross-region flow | `opts.flowOverrides[].transport` OR `asset.tags.transport` OR derivation from openPorts | Flow label renders `<class>:REQUIRES-OPERATOR-INPUT-transport`; `missing[]` += `transport:<from>-><to>`; coverage row `data_flow_transport.fill_rate` drops |
| Trust-boundary membership | D.D1's `fedramp_boundary=in/out` asset tag | When tag missing on an asset participating in a flow: trust-boundary `package` collapses to whole-diagram outer box + top note explaining the tag scheme + `missing[]` += `trust-boundary-tag-missing` |
| `tls_version` for HTTPS flows | Asset tag `tls_version=1.2|1.3` | Defaults to `TLS-1.3`; never silently substitute `TLS-1.0` or weak crypto. When operator wants TLS-1.2 explicitly, they tag it |
| Flow from cross-cloud edge | `opts.flowOverrides[]` (until INV-S7 ships cross-cloud edge discovery) | When an `externalEntities[]` entry's `type` is `external-system` AND no flowOverrides[] entry connects to it: rendered as a disconnected `actor` + `note: connect via --flow-overrides <path>` + `missing[]` += `cross-cloud-flow:<entity-name>` |

The slice never substitutes a "common" classification or a "common"
transport. UNCLASSIFIED is the explicit fallback that surfaces every
miss.

## Test specifications (≥15 tests)
1. `it('classifies S3 / GCS / Azure Blob as data stores')` — fixture
   with one S3 bucket + one GCS bucket + one Azure Storage container
   yields three `database` nodes.
2. `it('classifies EC2 / Compute Engine / VM as processes')` —
   fixture with one EC2 + one GCE instance + one Azure VM yields
   three `usecase` nodes.
3. `it('filters out infrastructure assets (VPCs, subnets, route tables)')` —
   fixture with one VPC + 2 subnets + 5 SGs yields zero DFD nodes for
   those assets; `manifest.infrastructure_filtered_count === 8`.
4. `it('emits actor nodes for opts.externalEntities[]')` — three
   external entities yields three `actor` blocks with their names.
5. `it('emits a single REQUIRES-OPERATOR-INPUT actor when no external entities supplied')`.
6. `it('emits labelled flow arrows from InventoryEdge[] with classification + transport')` —
   fixture with 2 edges yields 2 `-->` arrows with labels in the
   form `<class>:<transport>`.
7. `it('derives classification from source asset.dataClassification')` —
   source has `dataClassification=PII`, target is untagged → label
   begins with `PII:`.
8. `it('falls back to target asset.dataClassification when source missing')` —
   asserts the target's classification wins when source is untagged.
9. `it('renders UNCLASSIFIED + records missing[] when neither endpoint has dataClassification')`.
10. `it('derives transport from openPorts 443 → TLS-1.3')` — asset has
    `openPorts=[443]`, no `tls_version` tag → transport `TLS-1.3`.
11. `it('respects flowOverrides[] over tag derivation')` — even when
    asset has `dataClassification=PII`, a flowOverride with
    `classification=CUI` wins.
12. `it('emits doubled arrow ==> for flows crossing trust boundaries')` —
    fixture with `fedramp_boundary=in` on source + `fedramp_boundary=out`
    on target yields `==>` arrow.
13. `it('is deterministic — same input → byte-identical puml + manifest')` —
    runs twice, sha256s, asserts equality. Clock pinned to `runId`.
14. `it('writes diagram-manifest naming every flow with source InventoryEdge.from/to')`.
15. `it('throws MissingInventoryError when inventory.json absent')`.
16. `it('coverage-report data_classification fill_rate reflects tag presence per cloud')` —
    AWS fixture 3/5 tagged + GCP 5/5 tagged + Azure 0/2 tagged
    → rates 0.60 / 1.00 / 0.00.
17. `it('coverage-report data_flow_transport fill_rate reflects transport overrides + tag presence per cloud')`.
18. `it('exported buildDataFlowGraph() returns the same nodes+flows used in the PUML')` —
    asserts the graph data the rendering reads matches the data
    LOOP-G.G4 will consume.

(Total: 18 tests in `dataflow.test.ts`.)

## REO compliance specific to this slice
- **Every node** (entity / process / store) traces to either
  `asset.uniqueId` in `inventory.json` OR a programmatic
  `externalEntities[].name` OR a tag-derived `external_entity=...`.
- **Every flow** traces to either an `InventoryEdge` in
  `inventory.json` OR an operator-supplied `flowOverrides[]` entry.
  No fabricated edges.
- **Classification labels** come from real `asset.dataClassification`
  tag OR operator-supplied `flowOverrides[].classification`. Never
  defaulted to `Public` silently.
- **Transport labels** come from real `asset.openPorts` derivation
  (443 → TLS-1.3 unless tag overrides) OR
  `flowOverrides[].transport`. Never fabricated.
- **`synthesized_fields[]`** names every derived label (e.g.
  `'flow-label:PII:TLS-1.3 (openPorts-443-derivation)'`,
  `'transport:TLS-1.3 (default)'`,
  `'trust-boundary:in (fedramp_boundary tag)'`).
- **`unclassified_flow_count > 0`** triggers a `coverage:miss` line
  per asset on the run log AND surfaces in
  `inventory-coverage.json.data_classification`.
- **No "common-pattern" flow fabricated.** When a process has no
  incoming OR outgoing edges in inventory, it renders as an isolated
  node with `note: no inbound/outbound flow detected — verify INV-P3
  edge discovery for this asset` and a missing[] entry.
- **Signed by**: existing Ed25519 + RFC 3161 pipeline (allow-list
  already extended by D.D1).
- **CHANGELOG entry** names the slice + the module file + the test
  count delta + the verification result.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/dataflow.test.ts
npm run lint:no-stubs
npm run check:provenance
npm run check:coverage-regression
npm run check:reo
```

Spot-check live run:
```bash
cd cloud-evidence
node --import tsx core/orchestrator.ts \
  --aws --gcp --azure \
  --inventory \
  --dfd \
  --diagram-format=both \
  --external-entities=./external-entities.yaml \
  --flow-overrides=./flow-overrides.yaml \
  --out=out/dev
ls out/dev/dataflow.{puml,svg,png}
jq '.flow_count, .classified_flow_count, .unclassified_flow_count, .requires_operator_input' \
  out/dev/dataflow-diagram-manifest.json
```

## Known risks / issues
- **Risk R-D3-1 (high)**: `dataClassification` tags are operator-
  supplied and frequently absent at the start of a FedRAMP
  authorization. The diagram WILL render with many `UNCLASSIFIED`
  labels initially. **Mitigation**: the missing[] surface + coverage
  drop + run-log `coverage:miss` lines guide the operator to tag
  the assets. Document the tag scheme in
  `cloud-evidence/docs/loops/LOOP-D-SPEC.md` Appendix B (already done).
- **Risk R-D3-2 (high)**: cross-cloud edges (AWS Lambda → GCP
  Pub/Sub) are NOT captured by `InventoryEdge[]` until INV-S7 ships.
  Until then, cross-cloud flows must come from `flowOverrides[]`.
  **Mitigation**: when `opts.externalEntities[]` includes
  `type=external-system` AND no flowOverrides[] connects to it,
  emit a disconnected actor + missing[] entry with hint pointing to
  `--flow-overrides`. Document in the LOOP-D-SPEC open-questions
  section.
- **Risk R-D3-3 (med)**: classification taxonomy is opinionated
  (Public / Internal / CUI / PII / FOUO / Other). Operators with
  org-specific labels (e.g. "Restricted", "Sensitive") will use
  `Other` and lose the standard mapping. **Mitigation**: `Other`
  preserves the verbatim operator string; the manifest records both
  the original tag value AND the taxonomy mapping. A future slice
  can extend the enum.
- **Risk R-D3-4 (med)**: PII detection is tag-based, not content-
  based. A bucket actually containing PII but not tagged so will
  render as `UNCLASSIFIED` or `Public`. **Mitigation**: this is by
  design (REO standard rules out content-introspection). The
  operator's data-classification process is the source of truth.
  The slice is explicit about this in the source-file header.
- **Risk R-D3-5 (med)**: trust-boundary rendering depends on D.D1's
  `fedramp_boundary` tag. If D.D1 has not been run / tag is missing,
  the trust-boundary `package` collapses. **Mitigation**: D.D3 lists
  D.D1 in `depends_on:` so the spec's ordering encourages tagging
  first. The diagram still emits without the tag — just without the
  boundary visualization (with explicit missing[] entry).
- **Risk R-D3-6 (low)**: external-entity tag value parsing
  (`<name>:<type>`) is brittle if the entity name contains a colon
  (e.g. `IPv6: ::1`). **Mitigation**: tag value parser splits on
  the LAST `:` not the first; document in the source-file header.
  Tests cover the edge case.
- **Risk R-D3-7 (low)**: PlantUML `actor` + `usecase` + `database`
  in a single diagram can produce odd layout. **Mitigation**:
  layout is secondary to content; PlantUML jar fast-path uses
  Graphviz when available. The pure-TS subset renderer's layout is
  documented as "best-effort" in the LOOP-D-SPEC.
- **Risk R-D3-8 (low)**: `flowOverrides[]` can disagree with
  `InventoryEdge[]` (overrides classification of an edge that
  doesn't exist in inventory). **Mitigation**: when an override's
  `from`/`to` doesn't match any asset in inventory, emit
  `manifest.flow_override_orphans[]` with the offending entries
  AND missing[] entry; the diagram still renders the override
  (operator deliberately added it).

## Open questions (for implementation session to resolve)
- **Q1**: Should the DFD show ALL flows (including intra-process,
  e.g. ECS task → ECS task same service) or only flows that cross a
  process boundary? Intra-process is noise. Propose: filter
  intra-process flows (both endpoints in same process group); add
  `manifest.intra_process_filtered_count` integer.
- **Q2**: For `In-VPC-private` transport, do we still require a
  classification? Yes — data inside a VPC can still be CUI/PII and
  needs the label for SC-7 / AC-4 narrative. Propose: enforce
  classification for every flow regardless of transport.
- **Q3**: Should we render a "human user" actor automatically for
  every asset tagged `internet-facing=true`? Probably no — the
  operator declares external entities explicitly via
  `externalEntities[]`. Propose: do NOT auto-derive; document in
  the source-file header that operators MUST declare user classes.
- **Q4**: How granular should the `process` grouping be? One node
  per asset (could be hundreds for big fleets) vs one node per
  `(provider, assetType)` group (loses individual asset visibility).
  Propose: group by `(provider, assetType, application-tag)` with
  `count` suffix, mirroring D.D1's grouping. Manifest cites each
  underlying asset.
- **Q5**: Should `flowOverrides[]` support wildcard `from`/`to`
  (e.g. `from=ec2:*` to mean "any EC2 in the inventory")? Useful
  but complex. Propose: NO wildcards in v1; document as future
  enhancement. v1 requires exact `uniqueId` match.
- **Q6**: For CUI flows, do we render a small classification banner
  on the flow arrow (e.g. red bold `CUI`)? In Yourdon notation the
  label is the data type. PUML doesn't support arrow coloring
  natively but does support `-[#red,bold]->`. Propose: yes,
  CUI flows use `-[#red,bold]->`; PII uses `-[#orange,bold]->`;
  others default. The shared subset renderer already supports the
  `[#color,bold]` decoration (or extends it).
- **Q7**: When an asset has BOTH `dataClassification=PII` AND a
  trust-boundary crossing (`==>`), do we render the arrow as
  `==[#orange,bold]==>`? Yes — combine both decorations.
- **Q8**: Should `buildDataFlowGraph()` (the exported function for
  LOOP-G.G4 reuse) be in a separate file (e.g.
  `core/diagrams/dataflow-graph.ts`) or in `dataflow.ts`? Same
  file keeps it co-located with the rendering; separate file
  better signals it's a public API. Propose: same file, exported
  symbol named `buildDataFlowGraph` (lowercase `g` — same casing as
  the rest of the codebase).

## Implementation log (running journal — implementing session updates)
This section is filled in DURING implementation. Leave it empty with a
single placeholder line:
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 18 for this slice's new
      tests in `dataflow.test.ts`)
- [ ] check:reo green (G1 lint:no-stubs + G2 check:coverage-regression +
      G3 check:provenance)
- [ ] STATUS.md updated (D.D3 row + Overall section: last-shipped +
      next-priority; LOOP-D marked COMPLETE if D.D3 is the last)
- [ ] LOOP-D-SPEC.md §7 status table updated (D.D3 row)
- [ ] LOOP-D-SPEC.md heading flipped to "LOOP-D — Diagram Auto-Generation
      (COMPLETE)" if D.D3 is the last slice in the loop
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
      completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (under
      "### Added — LOOP-D.D3: Data Flow Diagram emitter (closes LOOP-D)")
- [ ] Commit with slice ID in message
      (`LOOP-D.D3: Data Flow Diagram emitter`)
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
4. Read `cloud-evidence/docs/slices/D/D.D1.md` to understand the three
   shared modules (`plantuml-render.ts`, `svg-to-png.ts`,
   `diagram-manifest.ts`) this slice REUSES (it does not redefine
   them). Also read D.D1.md to confirm `fedramp_boundary` tag
   semantics — D.D3 reuses them for trust-boundary rendering.
5. Read `cloud-evidence/docs/slices/D/D.D2.md` to see the
   PlantUML-subset extensions D.D2 made (if any) that this slice may
   build on.
6. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
7. Inspect `cloud-evidence/core/inventory-workbook.ts` for the
   `CloudAsset`, `InventoryEdge`, `InventorySnapshot` interfaces.
8. Inspect `cloud-evidence/core/inventory-emit.ts` for the
   `readPreviousInventory()` pattern this slice reuses.
9. Inspect `cloud-evidence/core/diagrams/plantuml-render.ts` (from
   D.D1) to confirm `actor`, `usecase`, `database`, `package`,
   `note`, and `-[#color,bold]->` arrow decorations are all in the
   grammar subset. Extend the subset if not, with a regression test.
10. Begin implementation; update the **Implementation log** section
    above as you go.

---

(end of D.D3 per-slice file)
