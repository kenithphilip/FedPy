# LOOP-D — Diagram Auto-Generation

> **Single source of truth** for the three slices in LOOP-D. A fresh
> session that opens this file (plus `cloud-evidence/CLAUDE.md` for the
> REO standard) has every detail it needs to ship D.D1, D.D2, and D.D3
> from scratch — no prior conversation required.

---

## 1. Why this loop exists

The FedRAMP authorization package mandates three graphical artifacts that
today are hand-drawn by 3PAOs / CSPs in Visio / Lucidchart / draw.io:

1. **Authorization Boundary Diagram (ABD)** — shows the logical boundary
   of the system being authorized, every component inside vs outside,
   every interconnection (managed / unmanaged), every shared-services
   / leveraged-cloud edge. Required by SSP Section 9 ("System
   Environment") and Appendix M ("Diagrams"). The diagram is the
   primary visual proof that the inventory-workbook scope matches the
   reality of the cloud account(s).

2. **Network Diagram (ND)** — VPC / VNet / VPC-network topology, each
   subnet labelled with CIDR + private/public, route tables, IGW/NAT,
   firewall rules summarised at the edge, peering and transit-gateway
   relationships. Multi-cloud aware. Required by SSP Section 9.3
   ("Network Architecture").

3. **Data Flow Diagram (DFD)** — asset-to-asset edges classifying the
   data flowing on each edge (PII / CUI / Public / Internal), the
   transport (TLS 1.2+ / mTLS / VPN), and the direction. The DFD is
   the visual companion to AC-4 (Information Flow Enforcement) and
   anchors the boundary-protection narrative in SC-7.

**The gap LOOP-D closes:** The CSP today re-draws all three diagrams by
hand on every authorization, on every Significant Change Notification
(SCN), and on every annual SSP review. Every hand-drawn diagram drifts
from real inventory the second a cloud resource is added or removed.
LOOP-D generates all three diagrams **directly from `inventory.json`
plus boundary / data-classification / interconnection tags**, so they
are byte-stable on identical inputs and never silently disagree with the
Integrated Inventory Workbook (Appendix M) or the SSP component table.

**Artifacts delivered per slice** (all three slices emit the same triple):
- `<diagram>.puml` — PlantUML source (text, deterministic, diff-able).
- `<diagram>.svg` — vector render. Embedded directly into the SSP .docx
  (LOOP-C / SSP-2) and the submission bundle (LOOP-A.A4).
- `<diagram>.png` — raster fallback for PDFs and screenshots.
- `<diagram>-manifest.json` — provenance: every node + edge cites its
  source asset.uniqueId or edge `from`/`to`, plus `synthesized_fields`
  for any computed label.

**Authorization-package gaps closed when LOOP-D ships:**
- SSP Section 9.1 ("Authorization Boundary") — boundary diagram filed.
- SSP Section 9.2 ("Network Architecture") — network diagram filed.
- SSP Section 9.3 ("Data Flow") — data flow diagram filed.
- Appendix M Diagrams tab — all three filed.
- SCN payloads (LOOP-E.E6) — diff-able diagram set per significant
  change.
- AFR-MAS-FLO (LOOP-G.G4) — information-flow diagram source reused.

---

## 2. Dependencies

### Prior loops/slices that must be complete

- **INV-P1 through INV-S6 (DONE)** — `out/inventory.json` is the only
  data source. `assets[]` carries `uniqueId`, `provider`, `accountId`,
  `location`, `assetType`, `resourceType`, `ips[]`, `vlanNetworkId`,
  `publicFacing`, `dataClassification`, `tags`, `diagramLabel`,
  `edges[]`. All three slices read from this snapshot.
- **REO-0 (DONE)** — REQUIRES-OPERATOR-INPUT pattern + lint guardrail.
- **LOOP-A.A4 (DONE)** — submission-bundle catalogue must learn the
  three new roles (extend `WELL_KNOWN`, see §4 per-slice).

### Existing files this loop extends or reads from

- `cloud-evidence/core/inventory-workbook.ts` — `CloudAsset`,
  `InventoryEdge`, `InventorySnapshot` interfaces (READ ONLY; do not
  redefine).
- `cloud-evidence/core/inventory-emit.ts` — `readPreviousInventory()`
  pattern; reuse the snapshot loader.
- `cloud-evidence/core/zip.ts` — `xmlEscape()` for SVG generation
  (PlantUML emits its own XML, but tag-attribute escaping is identical
  to the OOXML escape we already ship).
- `cloud-evidence/core/orchestrator.ts` — add three new flags (`--abd`,
  `--network-diagram`, `--dfd`) + envs (`CLOUD_EVIDENCE_ABD`,
  `CLOUD_EVIDENCE_NETWORK_DIAGRAM`, `CLOUD_EVIDENCE_DFD`). All three
  emitters run BEFORE signing so the diagrams are covered by the
  manifest and bundled into the submission tarball.
- `cloud-evidence/core/submission-bundle.ts` — extend `Role` union +
  `WELL_KNOWN[]` catalogue with six new entries (3 diagrams × 2 of
  {puml, svg, png}; manifest stays under generic provenance role).
- `cloud-evidence/core/sign.ts` — automatic. The sign module already
  picks up every `*.json`, `*.xml`, `*.pem` in `outDir`; we will
  extend its pattern set to include `*.puml`, `*.svg`, `*.png`,
  `*.diagram-manifest.json` so the three diagrams are signed alongside
  the OSCAL set.
- `cloud-evidence/core/inventory-coverage.ts` — add a `boundary_tag`
  coverage row per cloud so operators see when `fedramp_boundary=in`
  is missing on assets (this is what triggers D.D1's
  REQUIRES-OPERATOR-INPUT).

### Loops this loop unblocks

- **LOOP-E.E6 (formal SCN doc emitter)** — embeds the SVG triplet in
  the SCN notification.docx.
- **LOOP-G.G4 (AFR-MAS information-flow diagram)** — reuses
  `core/diagrams/dataflow.ts` `buildDataFlowGraph()` output.
- **LOOP-C.C9 (Baseline Configuration document)** — references the
  three SVGs.
- **LOOP-F.F4 (3PAO evidence walk-through)** — diagrams can be marked
  up in tracker, then re-emitted with assessor annotations.

LOOP-D itself depends on **nothing in LOOP-B / LOOP-C / LOOP-E /
LOOP-F / LOOP-G / LOOP-H / LOOP-I / LOOP-J / LOOP-K**. It is fully
parallel-safe.

---

## 3. Authoritative sources

### Primary (must be cited verbatim where quoted)

| URL / Document | Used for | Notes |
|---|---|---|
| `https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf` — *FedRAMP Authorization Boundary Guidance*, current published version | ABD required-elements list (D.D1) | The 26-page guidance enumerates every label the boundary diagram must carry. |
| `NIST SP 800-53 Rev5` (with patch release 5.2.0) — SC-7, AC-4, PL-2, CA-3 | ABD / ND / DFD control mapping | SC-7 boundary protection, AC-4 information-flow enforcement, PL-2 SSP authoritative documentation, CA-3 information exchange (interconnections). |
| `NIST SP 800-37 Rev2` — *Risk Management Framework for Information Systems and Organizations* | Boundary delineation (D.D1) | Section 2.4 "Authorization Boundaries" — the boundary diagram is the primary visualization of the system-of-record being authorized. |
| `RFC-0024` (FedRAMP 20x OSCAL submission RFC) | OSCAL prop-name + back-matter resource keys | Diagrams reference the SSP via OSCAL `back-matter.resources[]` with `rlinks[].media-type` = `image/svg+xml`. |
| `https://plantuml.com/` — PlantUML reference | Source language for D.D1 / D.D2 / D.D3 | Component / deployment / sequence diagrams. We emit `.puml` source. |
| `https://plantuml.com/component-diagram` | D.D1 syntax (component + package + interface + arrow) | Used for boundary boxes + interconnections. |
| `https://plantuml.com/deployment-diagram` | D.D2 syntax (node + cloud + database + arrow with protocol label) | Used for network topology. |
| `https://graphviz.org/doc/info/lang.html` — DOT language | D.D3 fallback / SVG layout engine | PlantUML uses Graphviz internally; understanding DOT helps debug layout. |
| `https://mermaid.js.org/syntax/c4.html` — Mermaid C4 model | Reference comparison (not emitted) | C4 model classifies into Context / Container / Component — informs D.D1 vs D.D2 vs D.D3 split. |
| Yourdon / DeMarco Structured Analysis DFD notation | D.D3 symbology | External entities (rectangles), processes (circles), data stores (open rectangles), data flows (labelled arrows). |

### Verbatim quotes used in this spec

**SC-7 Boundary Protection (NIST SP 800-53 Rev5, control statement):**

> "Monitor and control communications at the external managed
> interfaces to the system and at key internal managed interfaces
> within the system; implement subnetworks for publicly accessible
> system components that are physically or logically separated from
> internal organizational networks; and connect to external networks
> or systems only through managed interfaces consisting of boundary
> protection devices arranged in accordance with an organizational
> security and privacy architecture."

(Source: NIST SP 800-53 Rev5 §3.20 SC-7 control statement, as
published by the NIST CPRT catalog. Verify before quoting in code by
downloading `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
and locating SC-7 in the SC family appendix.)

**AC-4 Information Flow Enforcement (control statement):**

> "Enforce approved authorizations for controlling the flow of
> information within the system and between connected systems based
> on [Assignment: organization-defined information flow control
> policies]."

(Source: NIST SP 800-53 Rev5 §3.1 AC-4.)

**PL-2 System Security and Privacy Plans (control statement):**

> "Develop security and privacy plans for the system that ... describe
> the operational environment for the system and relationships with or
> connections to other systems ... [and] provide an overview of the
> security and privacy requirements for the system."

(Source: NIST SP 800-53 Rev5 §3.15 PL-2.)

**CA-3 Information Exchange (control statement):**

> "Approve and manage the exchange of information between the system
> and other systems using [Assignment: interconnection security
> agreements; information exchange security agreements; memoranda of
> understanding or agreement; service level agreements; user
> agreements; nondisclosure agreements; other types of agreements]."

(Source: NIST SP 800-53 Rev5 §3.5 CA-3.)

**FedRAMP Authorization Boundary Guidance — required diagram elements
(paraphrased from the guidance; verify verbatim when implementing):**

> "The Authorization Boundary Diagram (ABD) must depict every
> information system component that processes, stores, or transmits
> federal information within the boundary; every external system,
> service, or interconnection that crosses the boundary; the data
> flow direction and the type of data crossing each interface; and
> the FedRAMP authorization status of every leveraged service."

(Source: FedRAMP Authorization Boundary Guidance, "Required Elements"
section. The implementer MUST download the PDF and quote the
canonical list verbatim before shipping D.D1; the bullets above are
the operational requirements as widely reported in the FedRAMP
community of practice, but verbatim text from the guidance must be
the source of truth.)

### Required-element checklists (for inline use in tests + emit)

**ABD (D.D1) required elements per FedRAMP guidance:**
1. System name + system identifier (operator-supplied, REQUIRES-OPERATOR-INPUT if missing).
2. Impact level marker (Low / Moderate / High) in the title block.
3. The authorization boundary itself — a single enclosing labelled
   rectangle/cloud.
4. Every in-boundary component grouped by `(provider, assetType)`.
5. Every external interconnection (CSP-managed leveraged services
   like S3 / Cloud Storage; non-CSP interconnections like
   authorization-of-record agency systems) shown crossing the
   boundary line.
6. Authorization status label per leveraged service: "FedRAMP
   Authorized — <impact>" / "Non-FedRAMP" / "CSP-managed shared
   service".
7. Data-classification overlay on each crossing edge (Public / CUI /
   PII / FOUO / classified-out-of-scope).
8. Legend pane.
9. Date stamp + run-id footer.

**ND (D.D2) required elements:**
1. VPC / VNet / VPC-network containers per region.
2. Subnet rectangles inside containers, labelled with CIDR +
   public/private.
3. IGW / NAT / VPC endpoints / Cloud NAT.
4. Route table summary per subnet (default route + named routes).
5. Firewall (SG / NSG / firewall-rule) summary at the edge — top 5
   ingress + top 5 egress.
6. Peering / transit-gateway / VPN edges.
7. Cross-region edges if multi-region.
8. Public-facing component callouts.

**DFD (D.D3) required elements:**
1. External entity rectangles for each agency / human-user class /
   external system.
2. Process circles for each in-boundary asset group.
3. Data store open-rectangles for storage / database resources.
4. Data flow arrows with labels: `<data-classification>:<transport>`
   (e.g. `PII:TLS-1.3`, `CUI:VPN-IPsec`).
5. Trust-boundary dotted lines where data crosses encryption boundaries.
6. Direction arrows (one-way or bidirectional).

---

## 4. Per-slice implementation specs

### Slice D.D1 — Authorization Boundary Diagram

**Why this slice**: Closes the SSP §9.1 / Appendix M boundary-diagram
gap. Today CSPs hand-draw the ABD in Visio and it diverges from the
inventory the moment a resource is added or retired. This slice
generates a deterministic ABD from `inventory.json` + boundary tags so
the diagram is byte-stable on identical input and always agrees with
the workbook.

**Files to create**:
- `cloud-evidence/core/diagrams/boundary.ts` — pure builder + disk
  emitter. Reads `out/inventory.json`, emits `boundary.puml`,
  `boundary.svg`, `boundary.png`, `boundary-manifest.json`.
- `cloud-evidence/core/diagrams/plantuml-render.ts` — local
  PlantUML-source → SVG renderer (see §"PlantUML rendering strategy"
  below). Shared with D.D2 and D.D3.
- `cloud-evidence/core/diagrams/svg-to-png.ts` — pure-TS SVG
  rasteriser (see §"PNG strategy" below). Shared with D.D2 and D.D3.
- `cloud-evidence/core/diagrams/diagram-manifest.ts` — shared
  provenance writer (node-list + edge-list + computed-field
  provenance). Shared with D.D2 and D.D3.
- `cloud-evidence/tests/core/diagrams/boundary.test.ts` — ~14 tests.
- `cloud-evidence/tests/core/diagrams/plantuml-render.test.ts` — ~6
  tests (covered once for the shared module).
- `cloud-evidence/tests/core/diagrams/diagram-manifest.test.ts` — ~5
  tests (covered once for the shared module).

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts`:
  - Add CLI flag `--abd` + env `CLOUD_EVIDENCE_ABD` parsing.
  - Add `--diagram-format=svg|png|both` (default `both`) and env
    `CLOUD_EVIDENCE_DIAGRAM_FORMAT`.
  - Wire `emitBoundaryDiagram()` between inventory enrichment and
    signing.
  - Console log: `ABD: <n> in-boundary assets · <m> external
    interconnects · <k> REQUIRES-OPERATOR-INPUT markers`.
- `cloud-evidence/core/submission-bundle.ts`:
  - Extend `Role` union with `'boundary-diagram-puml'`,
    `'boundary-diagram-svg'`, `'boundary-diagram-png'`,
    `'diagram-manifest'`.
  - Append `WELL_KNOWN[]` entries:
    `{ role: 'boundary-diagram-puml', filename: 'boundary.puml', description: 'Authorization Boundary Diagram — PlantUML source' }`,
    `{ role: 'boundary-diagram-svg', filename: 'boundary.svg', description: 'Authorization Boundary Diagram — SVG render' }`,
    `{ role: 'boundary-diagram-png', filename: 'boundary.png', description: 'Authorization Boundary Diagram — PNG render' }`,
    `{ role: 'diagram-manifest', filename: /^(boundary|network|dataflow)-diagram-manifest\.json$/, description: 'Per-diagram provenance manifest naming every source asset' }`.
- `cloud-evidence/core/sign.ts`:
  - Extend file enumeration pattern set with `.puml`, `.svg`, `.png`,
    `.diagram-manifest.json` so all six outputs are covered by the
    signed manifest. (Verify the existing pattern by reading
    `core/sign.ts` enumeration; add the four extensions to the
    allow-list there.)
- `cloud-evidence/core/inventory-coverage.ts`:
  - Add `boundary_tag` coverage row to the registry:
    `aws: 'Asset tag fedramp_boundary=in|out (operator-supplied)'`,
    `gcp: 'Asset label fedramp_boundary=in|out'`,
    `azure: 'Asset tag fedramp_boundary=in|out'`.
  - When a run completes with `fedramp_boundary` absent on every
    asset, the coverage report records `boundary_tag.fill_rate = 0`
    AND the orchestrator emits a single `requires_operator_input`
    diagnostic naming the tag scheme.

**Schemas / standards used**:
- FedRAMP Authorization Boundary Guidance — required-elements list
  in §3 above.
- NIST SP 800-53 Rev5 SC-7 — boundary protection control text in §3.
- NIST SP 800-37 Rev2 §2.4 — boundary delineation.
- PlantUML component-diagram syntax (`https://plantuml.com/component-diagram`).
  Key tokens used:
  - `package "Name" as alias { ... }` for the boundary container.
  - `component "Label" as alias` for grouped in-boundary
    components.
  - `cloud "Service" as alias` for external CSP-leveraged services.
  - `[Component] --> [Other] : "label"` for crossing edges.
  - `note right of alias : "Authorized Moderate"` for status pins.
  - `legend right ... end legend` for the legend pane.
- OSCAL v1.1.2 `back-matter.resources[]` — the SSP/AP/AR (LOOP-A)
  back-matter MAY reference the SVG via `rlinks: [{ media-type: "image/svg+xml", href: "./boundary.svg" }]`.
  Adding the back-matter wiring is a follow-up; the diagram itself
  ships first.

**Build steps**:

1. Define interfaces in `core/diagrams/boundary.ts`:
   ```ts
   export interface BoundaryDiagramOptions {
     outDir: string;
     systemName?: string;
     systemId?: string;
     impactLevel: 'low' | 'moderate' | 'high';
     runId: string;
     /** Emit format(s). Default: ['puml', 'svg', 'png']. */
     formats?: Array<'puml' | 'svg' | 'png'>;
     /** Operator override: explicit list of leveraged-service edges. */
     leveragedServices?: Array<{ name: string; status: 'fedramp-authorized' | 'non-fedramp' | 'csp-managed-shared' }>;
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

2. Pure builder function:
   ```ts
   export function buildBoundaryPuml(
     snapshot: InventorySnapshot,
     opts: BoundaryDiagramOptions
   ): { puml: string; nodes: BoundaryNode[]; edges: BoundaryEdge[]; missing: string[] }
   ```
   Behaviour:
   - Read `fedramp_boundary` from `asset.tags` (case-insensitive, also
     accepts `fedramp-boundary` and `boundary`).
   - Assets with `fedramp_boundary === 'in'` → grouped into
     `package "Authorization Boundary"`.
   - Assets with `fedramp_boundary === 'out'` → grouped into
     `package "External Systems"`.
   - When NO asset has the tag, every asset is rendered with a
     `note bottom: REQUIRES-OPERATOR-INPUT — tag asset with fedramp_boundary=in|out`
     and the boundary container itself carries a top-of-diagram note
     describing the tag scheme. The build does not throw — it emits a
     **structurally complete diagram with explicit markers** so the
     operator sees exactly what to fix.
   - Group in-boundary assets by `(provider, assetType)`. Render one
     `component "<provider>·<assetType> (n=<count>)" as <slug>` per
     group. The count drives at-a-glance scale.
   - For each `InventoryEdge` whose `from`/`to` cross a
     boundary-group pair (one in, one out), emit a crossing arrow
     with the data-classification label.
   - Render leveraged services from `opts.leveragedServices` (or from
     assets tagged `leveraged_service=<name>:<status>`) as `cloud`
     nodes outside the boundary, each annotated with the status.
   - Title block:
     `title <systemName> — Authorization Boundary Diagram\n<impactLevel> · runId=<id> · generated <ISO-date>`.
   - When `systemName` is missing, the title gets
     `REQUIRES-OPERATOR-INPUT (--system-name)` and the missing array
     gets `'systemName'`.
   - Legend pane bottom-right enumerating the four group types.

3. Disk emitter:
   ```ts
   export function emitBoundaryDiagram(opts: BoundaryDiagramOptions): BoundaryDiagramResult
   ```
   - Reads `out/inventory.json`. If absent, throws a typed
     `MissingInventoryError` naming the orchestrator step that should
     have produced it.
   - Calls `buildBoundaryPuml(snapshot, opts)`.
   - Writes `<outDir>/boundary.puml` (always).
   - If `formats` includes `svg`, renders SVG via
     `renderPumlToSvg(puml)` (shared module).
   - If `formats` includes `png`, rasterises SVG via
     `svgToPng(svg, { width: 1600 })` (shared module).
   - Writes `<outDir>/boundary-diagram-manifest.json` enumerating
     every `node` (cites `asset.uniqueId` or `synthesized: true`) and
     every `edge` (cites `InventoryEdge.from`/`to`).

4. Wire into orchestrator:
   - Flag: `--abd`. Env: `CLOUD_EVIDENCE_ABD=1`. Format selector:
     `--diagram-format=svg|png|both|puml-only` /
     `CLOUD_EVIDENCE_DIAGRAM_FORMAT`.
   - Runs after `applyDiagramLabelAndComments` (INV-S6) and BEFORE
     `signEvidence()` so the diagram is covered by the manifest.
   - Console line: `ABD: in=<n> out=<m> interconnects=<k> input=<missing-count> [puml svg png]`.

5. Submission-bundle catalogue: as described in "Files to extend".

**PlantUML rendering strategy** (shared `core/diagrams/plantuml-render.ts`):

There are two viable paths; the spec MANDATES path (a) and documents
path (b) as a fallback an operator can enable.

(a) **`plantuml.jar` via a local subprocess** — the reference C4 / PUML
renderer. The orchestrator looks for `plantuml.jar` in this order:
`$CLOUD_EVIDENCE_PLANTUML_JAR` env, then `which plantuml`, then
`/usr/local/lib/plantuml.jar`, then `/opt/homebrew/Cellar/plantuml/*/libexec/plantuml.jar`.
When found, the renderer invokes:
`java -jar <jar> -tsvg -pipe < <puml-source> > <svg-out>`.
The renderer captures stdout, validates the result begins with
`<?xml` or `<svg`, and writes to disk.

(b) **Pure-TS PlantUML subset** — When `plantuml.jar` is not installed,
the renderer falls back to a pure-TypeScript SVG generator
implemented in `core/diagrams/plantuml-render.ts` that supports the
subset of PlantUML this loop uses (packages, components, clouds,
labelled arrows, notes, title, legend). The subset is documented in
the source-file header with a verbatim grammar listing. This avoids a
Java runtime dependency in CI / on Phase Two pilot runners.

Both paths are tested:
- (a) is verified by piping a known-good `.puml` through the
  subprocess (test gated on `which java`; skipped cleanly in CI when
  Java absent).
- (b) is verified by SVG well-formedness assertions against the
  subset.

The implementer ships path (b) first (no external dep), then layers
path (a) as an optional fast-path. The fallback NEVER silently
returns an empty SVG — when neither path can render, it throws
`PlantUMLRenderError` with a message naming both fallbacks the
operator can install. **REO Rule 1 #5 forbids silent fallback.**

**PNG strategy** (shared `core/diagrams/svg-to-png.ts`):

Same two-path approach:
(a) When `sharp` is already installed (we check
`require.resolve('sharp')` defensively without adding a hard dep),
use it.
(b) Otherwise emit a minimal PNG via the Node-native `canvas`
fallback: render the SVG into a 1600×1200 RGBA buffer using a tiny
pure-TS SVG parser (subset: rectangles, text, lines, paths). Output
via `node:zlib` deflate + manual PNG chunks (we already have the
crc32 helper in `core/zip.ts`).

The PNG fallback is documented in the spec but the implementer MAY
ship only path (a) with `sharp` opt-in if the pure-TS PNG generator
exceeds the LOOP-D timebox — in that case PNG emission becomes
opt-in via `--diagram-format=svg+png` (with a typed warning when
`sharp` is unavailable). The SVG is the canonical output that
operators reference everywhere.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | When triggered | Surface |
|---|---|---|
| `fedramp_boundary` asset tag | NO asset in `inventory.json` carries `fedramp_boundary=in\|out` | `boundary-diagram-manifest.json.requires_operator_input[].field` + diagram top-banner note + coverage-report row |
| `systemName` | `--system-name` and `CLOUD_EVIDENCE_SYSTEM_NAME` both unset | Title block carries `REQUIRES-OPERATOR-INPUT (--system-name)` + missing[] |
| `systemId` | `--system-id` / env both unset | Subtitle carries marker + missing[] |
| `leveraged_service` tags | Operator wants a CSP-managed-shared / FedRAMP-Authorized leveraged service rendered explicitly | Tag asset `leveraged_service=Amazon-S3:fedramp-authorized` OR pass via `BoundaryDiagramOptions.leveragedServices[]` |
| Data-classification edge labels | Edge between in- and out-boundary groups with no `dataClassification` on either endpoint | Edge label renders `REQUIRES-OPERATOR-INPUT` + missing[].field = `dataClassification:<from>-><to>` |

**Test specifications** (boundary.test.ts):

1. `it('emits puml + svg + png + manifest in default mode', ...)` — runs against a 3-asset fixture, asserts all four files exist + bytes > 0.
2. `it('groups in-boundary assets by (provider, assetType) with count', ...)` — fixture with 5 EC2 + 2 RDS + 3 GCS yields three groups labelled with `n=`.
3. `it('emits REQUIRES-OPERATOR-INPUT banner when no asset has fedramp_boundary tag', ...)` — asserts `boundary.puml` contains `REQUIRES-OPERATOR-INPUT` literal + result.requires_operator_input contains `'fedramp_boundary_tag_missing'`.
4. `it('respects fedramp_boundary=in vs out and renders separate packages', ...)`
5. `it('renders leveraged-service cloud nodes outside the boundary with status label', ...)`
6. `it('marks edges crossing the boundary with data-classification label from asset.dataClassification', ...)`
7. `it('emits REQUIRES-OPERATOR-INPUT on a crossing edge when neither endpoint has dataClassification', ...)`
8. `it('renders title block with systemName + impactLevel + runId + generated timestamp', ...)`
9. `it('emits REQUIRES-OPERATOR-INPUT marker in title when systemName missing', ...)`
10. `it('is deterministic — identical inputs → byte-identical puml', ...)` — runs twice, compares hashes.
11. `it('throws MissingInventoryError when inventory.json absent', ...)`
12. `it('writes a diagram-manifest naming every node + every edge with its source asset.uniqueId', ...)`
13. `it('honors --diagram-format=puml-only (no svg/png written)', ...)`
14. `it('omits PNG cleanly when neither sharp nor pure-TS fallback available, with a typed warning', ...)`
15. `it('coverage-report row boundary_tag.fill_rate reflects tag presence', ...)` — fixture with 5/5 tagged → 100%, 0/5 tagged → 0%.

**REO compliance checks specific to this slice**:
- Every node in the rendered PUML traces to an `asset.uniqueId` in
  `inventory.json` OR to an operator-supplied
  `leveragedServices[]` entry.
- Every edge traces to an `InventoryEdge` in `inventory.json` OR to a
  tag-derived `leveraged_service=...` declaration.
- The `boundary-diagram-manifest.json` `nodes[].source` and
  `edges[].source` fields are mandatory and assert against the
  inventory snapshot used.
- No silent fallback in the renderer: when no rendering path
  works, throw — never write a placeholder image.
- `synthesized_fields[]` on the manifest names every label the
  emitter computed (e.g. `'group-label:aws·ec2 (n=5)'`).

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/boundary.test.ts
npm test -- tests/core/diagrams/plantuml-render.test.ts
npm test -- tests/core/diagrams/diagram-manifest.test.ts
npm run lint:no-stubs
npm run check:provenance
npm run check:reo
```

**Estimated effort**: 4–5 days (the PlantUML subset renderer is the
load-bearing piece; once it lands, D.D2 + D.D3 reuse it).

---

### Slice D.D2 — Network Diagram

**Why this slice**: Closes the SSP §9.2 ("Network Architecture") gap.
The network diagram is the visual companion to the boundary diagram
and the primary artifact a 3PAO uses to map firewall rules to SC-7
controls. Today it's hand-drawn; LOOP-D.D2 generates it from real
VPC / VNet / VPC-network discovery already in `inventory.json`.

**Files to create**:
- `cloud-evidence/core/diagrams/network.ts` — pure builder + disk
  emitter. Reads `out/inventory.json`, emits `network.puml`,
  `network.svg`, `network.png`, `network-diagram-manifest.json`.
- `cloud-evidence/tests/core/diagrams/network.test.ts` — ~13 tests.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts`:
  - Add CLI flag `--network-diagram` + env
    `CLOUD_EVIDENCE_NETWORK_DIAGRAM`.
  - Runs after `--abd` (when both flagged) so the bundler sees both.
  - Console: `ND: <regions> regions · <vpcs> VPCs · <subnets> subnets · <fw-rules> rule-summaries`.
- `cloud-evidence/core/submission-bundle.ts`:
  - Extend `Role` union: `'network-diagram-puml'`,
    `'network-diagram-svg'`, `'network-diagram-png'`.
  - `WELL_KNOWN[]` append:
    `{ role: 'network-diagram-puml', filename: 'network.puml', description: 'Network Diagram — PlantUML source' }`,
    `{ role: 'network-diagram-svg', filename: 'network.svg', description: 'Network Diagram — SVG render' }`,
    `{ role: 'network-diagram-png', filename: 'network.png', description: 'Network Diagram — PNG render' }`.
- `cloud-evidence/core/inventory-coverage.ts`:
  - No new column. ND consumes existing `vlan_network_id` (column U)
    + `ip_address` (column C) + `public` (column D) coverage rows.

**Schemas / standards**:
- NIST SP 800-53 Rev5 SC-7 (control statement quoted in §3 above) —
  network segmentation + boundary devices.
- NIST SP 800-53 Rev5 SC-7(3), SC-7(4), SC-7(5) — managed
  interfaces, restrict external traffic, deny by default.
- FedRAMP Authorization Boundary Guidance, "Network Architecture"
  section — IGW, NAT, peering, transit-gateway visibility required.
- PlantUML deployment-diagram syntax
  (`https://plantuml.com/deployment-diagram`):
  - `cloud "AWS / <region>" as awsr1 { ... }` for cloud-region
    container.
  - `node "VPC <id> · <cidr>" as vpcA { ... }` for VPC nodes.
  - `frame "subnet <id> · <cidr> · public" as subA1 { ... }` for
    subnet rectangles inside a VPC.
  - `database "RDS-<id>" as db1` for stateful nodes.
  - `vpcA --[#blue,bold]-> tgwHub : "rfc1918 east-west"` for
    peering / transit-gateway labelled arrows.
- AWS VPC: `Vpc`, `Subnet`, `RouteTable`, `InternetGateway`,
  `NatGateway`, `VpcPeeringConnection`, `TransitGateway`,
  `TransitGatewayVpcAttachment`, `SecurityGroup` (already enumerated
  by `providers/aws/network.ts`).
- GCP VPC: `compute.googleapis.com/Network`,
  `compute.googleapis.com/Subnetwork`, `compute.googleapis.com/Route`,
  `compute.googleapis.com/Firewall`, `compute.googleapis.com/Router`.
- Azure VNet: `Microsoft.Network/virtualNetworks`,
  `Microsoft.Network/virtualNetworks/subnets`,
  `Microsoft.Network/routeTables`,
  `Microsoft.Network/networkSecurityGroups`,
  `Microsoft.Network/virtualNetworkPeerings`.

**Build steps**:

1. Define interfaces:
   ```ts
   export interface NetworkDiagramOptions {
     outDir: string;
     runId: string;
     /** Show top-N firewall rules per direction (default 5). */
     firewallRuleSummaryLimit?: number;
     formats?: Array<'puml' | 'svg' | 'png'>;
     /** Optionally restrict to a subset of providers. */
     providers?: Array<'aws' | 'gcp' | 'azure'>;
   }
   export interface NetworkDiagramResult {
     paths: { puml?: string; svg?: string; png?: string; manifest: string };
     region_count: number;
     vpc_count: number;
     subnet_count: number;
     firewall_rule_count: number;
     peering_count: number;
     bytes: number;
     requires_operator_input: string[];
   }
   ```

2. Pure builder:
   ```ts
   export function buildNetworkPuml(
     snapshot: InventorySnapshot,
     opts: NetworkDiagramOptions
   ): { puml: string; nodes: NetNode[]; edges: NetEdge[]; missing: string[] }
   ```
   Behaviour:
   - Group `assets[]` by provider, then by region (`location`).
     Emit one `cloud "<Provider> / <region>"` per (provider, region).
   - Inside each region, group assets by `resourceType` matching one
     of the VPC/VNet types listed above. Emit:
     - `node` for each VPC / VNet / network.
     - `frame` for each subnet inside its parent network. Subnet
       label format: `<id> · <cidr> · <public|private>`. Public is
       inferred from `publicFacing` of any asset in the subnet
       (carried through inventory enrichment).
     - `database` for each DB asset (RDS / Cloud SQL / Azure SQL),
       placed inside its subnet.
   - Edges:
     - Peering / transit-gateway connections from
       `InventoryEdge[]` with `type` matching
       `/^(peering|tgw-attachment|vpn|interconnect)$/`.
     - IGW / NAT / Cloud-NAT nodes attached to their owning VPC.
   - Firewall rule summary:
     - For each VPC/VNet, find the most-permissive ingress rule
       (sort by `port range size desc`, then by `cidr size desc`)
       and the most-restrictive deny rule. Emit a `note right of
       <vpc-alias>` listing up to `firewallRuleSummaryLimit` rules
       per direction.
     - **REO note**: The rule summary cites the source
       `SecurityGroup` / `NSG` / `Firewall` `uniqueId` in the
       manifest. No rule is invented.
   - Title:
     `title Network Diagram\nrunId=<id> · generated <ISO-date>`.

3. Disk emitter: pattern identical to D.D1.

4. Wire into orchestrator: flag, env, format selector, console log.

5. Bundler: extend Role + WELL_KNOWN.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | When triggered | Surface |
|---|---|---|
| Subnet CIDR | Asset has `vlanNetworkId` but the parent VPC/VNet does not appear in `inventory.json` (orphan subnet) | Subnet rendered with `CIDR: REQUIRES-OPERATOR-INPUT` + manifest.requires_operator_input |
| Firewall rule context | A rule references `cidr: 0.0.0.0/0` on a private subnet | `note right` includes `REQUIRES-OPERATOR-INPUT: justify 0.0.0.0/0 rule on subnet <id>` |
| Cross-region edge purpose | Peering edge between two regions with no `application` tag on either side | Edge label appends `REQUIRES-OPERATOR-INPUT: peering-purpose` |

**Test specifications** (network.test.ts):
1. `it('groups assets by provider+region into cloud containers', ...)`
2. `it('emits one node per VPC / VNet / network', ...)`
3. `it('emits one frame per subnet inside its parent VPC with cidr + public/private label', ...)`
4. `it('emits database nodes for RDS / Cloud SQL / Azure SQL placed in their subnet', ...)`
5. `it('emits peering/transit-gateway/vpn arrows from InventoryEdge[]', ...)`
6. `it('emits firewall rule summary note with top-N rules per direction', ...)` — fixture with 12 rules + limit=5 → only 5 listed.
7. `it('the rule summary cites every rule by SecurityGroup uniqueId in the manifest', ...)`
8. `it('emits REQUIRES-OPERATOR-INPUT for orphan subnet (no parent VPC)', ...)`
9. `it('emits REQUIRES-OPERATOR-INPUT for 0.0.0.0/0 rule on private subnet', ...)`
10. `it('respects --providers=aws to skip GCP/Azure assets', ...)`
11. `it('is deterministic — same input → byte-identical puml', ...)`
12. `it('throws MissingInventoryError when inventory.json absent', ...)`
13. `it('writes diagram-manifest naming every VPC/subnet/peering edge with source uniqueId', ...)`
14. `it('coverage-report fields vlan_network_id + ip_address are read but not modified', ...)` — sanity check we don't accidentally bump coverage from this slice.

**REO compliance checks specific to this slice**:
- Every VPC / subnet / peering node is sourced from a real
  `InventorySnapshot.assets[]` or `InventorySnapshot.edges[]` entry.
- Firewall rule summary is sourced from real SG / NSG / Firewall
  resources (provider collectors already enumerate these into
  `asset.raw` or `asset.openPorts`).
- No "common-pattern" rule fabricated. When a rule cannot be
  resolved from inventory, the summary cell renders empty (NOT a
  placeholder).
- `network-diagram-manifest.json.firewall_rules[]` cites
  `securityGroup.uniqueId` + `ruleIndex` + `direction` + `port` +
  `cidr` + `protocol`.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/network.test.ts
npm run check:reo
```

**Estimated effort**: 3–4 days.

---

### Slice D.D3 — Data Flow Diagram

**Why this slice**: Closes the SSP §9.3 ("Data Flow") gap and seeds
the AFR-MAS information-flow diagram for LOOP-G.G4. The DFD anchors
the AC-4 (Information Flow Enforcement) narrative. Today it's hand-
drawn; LOOP-D.D3 derives it from real asset-to-asset relationships
in `inventory.json` (RDS → EC2, S3 → Lambda, Pub/Sub → Functions,
etc.) plus data-classification tags.

**Files to create**:
- `cloud-evidence/core/diagrams/dataflow.ts` — pure builder + disk
  emitter. Reads `out/inventory.json`, emits `dataflow.puml`,
  `dataflow.svg`, `dataflow.png`, `dataflow-diagram-manifest.json`.
- `cloud-evidence/tests/core/diagrams/dataflow.test.ts` — ~14 tests.

**Files to extend**:
- `cloud-evidence/core/orchestrator.ts`:
  - Add CLI flag `--dfd` + env `CLOUD_EVIDENCE_DFD`.
  - Console: `DFD: <entities> entities · <processes> processes · <stores> stores · <flows> flows · <input-required> markers`.
- `cloud-evidence/core/submission-bundle.ts`:
  - Extend `Role`: `'dataflow-diagram-puml'`,
    `'dataflow-diagram-svg'`, `'dataflow-diagram-png'`.
  - `WELL_KNOWN[]` append:
    `{ role: 'dataflow-diagram-puml', filename: 'dataflow.puml', description: 'Data Flow Diagram — PlantUML source' }`,
    `{ role: 'dataflow-diagram-svg', filename: 'dataflow.svg', description: 'Data Flow Diagram — SVG render' }`,
    `{ role: 'dataflow-diagram-png', filename: 'dataflow.png', description: 'Data Flow Diagram — PNG render' }`.
- `cloud-evidence/core/inventory-coverage.ts`:
  - Add `data_classification` coverage row per cloud (tag-derived).
  - Add `data_flow_transport` row per cloud (operator-supplied via
    edge metadata).

**Schemas / standards**:
- NIST SP 800-53 Rev5 AC-4 (quoted in §3 above).
- NIST SP 800-53 Rev5 CA-3 (quoted in §3 above).
- Yourdon / DeMarco DFD notation (1979-era classic structured-
  analysis symbology):
  - External entity = rectangle (rendered as `actor` in PlantUML or
    `rectangle` shape).
  - Process = circle (rendered as PlantUML `usecase` round-shape or
    DOT `ellipse`).
  - Data store = open rectangle (rendered as PlantUML `database` or
    DOT `cylinder`).
  - Data flow = labelled arrow (PlantUML `-->` with the label
    carrying `<classification>:<transport>`).
- PlantUML use-case + component blend (since DFDs don't have a
  canonical PlantUML diagram type, we emit a hybrid):
  - `actor "Agency System" as agency` for external entities.
  - `usecase "Process: <name>" as proc1` for processes.
  - `database "<store-name>" as ds1` for data stores.
  - `agency --> proc1 : "PII : TLS-1.3"` for flows.
- Data classification taxonomy (operator-supplied via tags;
  emit-side enum):
  - `Public` (no marking).
  - `Internal` (organisationally-internal).
  - `CUI` (Controlled Unclassified Information — must show on flow).
  - `PII` (Personally Identifiable Information).
  - `FOUO` (For Official Use Only).
  - `Other` (operator-named).
- Transport taxonomy (derived from existing inventory fields +
  operator-supplied edge metadata):
  - `TLS-1.2` / `TLS-1.3` (derived from `asset.openPorts` 443 +
    operator confirmation).
  - `mTLS` (tagged `transport=mtls` or inferred from service-mesh
    asset).
  - `VPN-IPsec` / `VPN-Wireguard` (operator-supplied).
  - `RDS-native` / `Cloud-SQL-native` (proxied through the cloud's
    TLS-mandatory database protocol).
  - `In-VPC-private` (asset is in a private subnet; transport is
    in-cloud private — but the data classification still applies).

**Build steps**:

1. Define interfaces:
   ```ts
   export interface DataFlowDiagramOptions {
     outDir: string;
     runId: string;
     /** External entities the operator wants explicitly shown. */
     externalEntities?: Array<{ name: string; type: 'agency' | 'user-class' | 'external-system' }>;
     /** Operator-supplied per-edge metadata (overrides tag derivation). */
     flowOverrides?: Array<{ from: string; to: string; classification: string; transport: string }>;
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
   ```

2. Pure builder:
   ```ts
   export function buildDataFlowPuml(
     snapshot: InventorySnapshot,
     opts: DataFlowDiagramOptions
   ): { puml: string; nodes: DfdNode[]; flows: DfdFlow[]; missing: string[] }
   ```
   Behaviour:
   - **Classify each asset** into one of three DFD primitives:
     - `assetType` matches `/storage|bucket|s3|gcs|blob|disk|database|sql|dynamodb|firestore|cosmos|table|warehouse/i` → data store.
     - `assetType` matches `/instance|compute|vm|function|lambda|cloud-run|cloud-function|container|task|service|aks|gke|eks/i` → process.
     - Otherwise → "infrastructure" (folded into the parent
       process / store; not drawn as its own node).
   - **External entities**: emit `actor` nodes for every
     `opts.externalEntities[]` entry. If none supplied, derive a
     single `actor "Agency Tenant" as tenantActor` with
     `REQUIRES-OPERATOR-INPUT: external-entities`.
   - **Flows from edges**: for each `InventoryEdge` whose endpoints
     are both classified (one process, one store / one external,
     one process / etc.), emit a labelled arrow.
   - **Flow label rules**:
     - Classification: read `dataClassification` from the *source*
       asset; if missing, read from the *target*; if both missing,
       use `'UNCLASSIFIED'` and add to `missing[]`.
     - Transport: prefer `flowOverrides[].transport`; else derive
       from asset.openPorts (443 → TLS-1.3 unless `tls_version`
       tag says otherwise); else `'In-VPC-private'` for edges
       where both endpoints share `vlanNetworkId`.
   - **Trust boundary lines**: emit a PlantUML `note` group around
     groups of nodes that share a trust boundary (defined as
     `assets sharing the in-boundary group from D.D1`). Flows
     crossing trust boundaries get a doubled arrow `==>`.
   - **Title**:
     `title Data Flow Diagram\nrunId=<id> · generated <ISO-date>`.

3. Disk emitter: identical pattern.

4. Orchestrator wiring + bundler catalogue: as described.

**REQUIRES-OPERATOR-INPUT fields**:

| Field | When triggered | Surface |
|---|---|---|
| `dataClassification` asset tag | Asset participates in an edge but has no `dataClassification` | Flow label renders `UNCLASSIFIED:<transport>` + missing[].field = `dataClassification:<asset.uniqueId>` |
| `externalEntities[]` | No `opts.externalEntities` supplied + no asset tagged `external_entity=...` | Single placeholder `actor "Agency Tenant" REQUIRES-OPERATOR-INPUT` + missing[].field = `externalEntities` |
| Transport for cross-region flow | Flow crosses regions with no `transport` tag and no `flowOverrides` entry | Flow label renders `<class>:REQUIRES-OPERATOR-INPUT-transport` + missing[] |
| Trust-boundary membership | Asset has no `fedramp_boundary` tag (same as D.D1 dependency) | Trust-boundary line collapses to the whole-diagram outer box + a top note explaining the tag scheme |

**Test specifications** (dataflow.test.ts):
1. `it('classifies S3 / GCS / Azure Blob as data stores', ...)`
2. `it('classifies EC2 / Compute Engine / VM as processes', ...)`
3. `it('emits actor nodes for opts.externalEntities[]', ...)`
4. `it('emits a single REQUIRES-OPERATOR-INPUT actor when no external entities supplied', ...)`
5. `it('emits labelled flow arrows from InventoryEdge[] with classification + transport', ...)`
6. `it('derives classification from source asset.dataClassification', ...)`
7. `it('falls back to target asset.dataClassification when source missing', ...)`
8. `it('renders UNCLASSIFIED + records missing[] when neither endpoint has dataClassification', ...)`
9. `it('derives transport from openPorts 443 → TLS-1.3', ...)`
10. `it('respects flowOverrides[] over tag derivation', ...)`
11. `it('emits doubled arrow ==> for flows crossing trust boundaries', ...)`
12. `it('is deterministic — same input → byte-identical puml', ...)`
13. `it('writes diagram-manifest naming every flow with source InventoryEdge.from/to', ...)`
14. `it('throws MissingInventoryError when inventory.json absent', ...)`
15. `it('coverage-report records data_classification fill_rate per cloud', ...)`

**REO compliance checks specific to this slice**:
- Every node (entity / process / store) traces to either
  `asset.uniqueId` or `externalEntities[].name`.
- Every flow traces to an `InventoryEdge` OR a
  `flowOverrides[]` entry.
- Classification labels come from real `asset.dataClassification`
  OR from operator-supplied `flowOverrides[].classification`.
- Transport labels come from real `asset.openPorts` + operator
  override; never fabricated.
- `dataflow-diagram-manifest.json.synthesized_fields[]` names
  every derived label.
- `unclassified_flow_count > 0` triggers a coverage:miss line per
  asset on the run log AND surfaces in
  `inventory-coverage.json.data_classification`.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/dataflow.test.ts
npm run check:reo
```

**Estimated effort**: 4 days.

---

## 5. Loop-wide acceptance criteria

When all three slices are complete:

1. `npm run typecheck` is clean (no `any`-leaks, no unused exports).
2. All ~46 new tests pass (boundary 14 + plantuml-render 6 +
   diagram-manifest 5 + network 13 + dataflow 14 + shared svg-to-png
   smoke ~4 = 56 tests minimum). The CHANGELOG entries cite the
   exact test counts.
3. `npm run check:reo` (G1 + G2 + G3) returns 0:
   - G1: no `TODO` / `placeholder` / `stub` / `sample` / `lorem` /
     `not yet implemented` tokens in any new `core/diagrams/*.ts`.
   - G2: no inventory-coverage fill-rate regression caused by the
     new `boundary_tag` / `data_classification` / `data_flow_transport`
     rows. (They start at whatever the live tag-rate is — that's a
     measurement, not a regression.)
   - G3: `boundary-diagram-manifest.json`,
     `network-diagram-manifest.json`,
     `dataflow-diagram-manifest.json` each carry a top-level
     `provenance` block with `emitter`, `emittedAt`, `sourceCalls`,
     `signingKeyId` matching the existing inventory-emit provenance
     pattern.
4. `out/manifest.json` (the signed manifest) covers every emitted
   diagram artefact (`*.puml`, `*.svg`, `*.png`,
   `*-diagram-manifest.json`).
5. `out/submission-package.tar.gz` (LOOP-A.A4) contains all nine
   diagram outputs (3 diagrams × 3 formats) plus the three manifests.
6. The orchestrator help text lists the three new flags + the
   `--diagram-format` selector.
7. CHANGELOG.md "Unreleased" has three new entries naming the
   slices, the module files, and the verification counts.
8. `docs/STATUS.md` (if present) is updated to "LOOP-D: COMPLETE".
9. A live run on the dev fixture (`out/fixtures/inventory-mini.json`,
   3 AWS + 2 GCP + 1 Azure asset) produces all nine files and a
   manifest in under 30 seconds wall-clock.
10. SSP-2 (SSP .docx renderer, already shipped) is wired to embed the
    three SVGs into SSP §9.1 / §9.2 / §9.3 when the SVGs exist on
    disk. (Wiring is a one-line `existsSync()` check; the
    SSP-emitter section is a single render-pass that inlines the SVG
    base64-encoded into a `<w:pict>` element.)

---

## 6. Open questions / caveats

1. **`plantuml.jar` distribution**: shipping a Java dependency is
   undesirable. The spec mandates a pure-TS subset renderer first
   (`core/diagrams/plantuml-render.ts` path (b)) so CI / Phase Two
   pilot runners stay dep-free. If the subset misses a needed shape
   during D.D2 (network deployment-diagram syntax has more variants),
   add the shape to the subset rather than punting to the jar.

2. **PNG generation in pure JS**: rasterising arbitrary SVG to PNG
   without a headless browser is non-trivial. The spec allows
   shipping SVG-only if PNG generation exceeds timebox, with a clear
   typed warning to operators who request `--diagram-format=png`.
   The PNG is convenience; the SVG is canonical.

3. **C4 vs PUML notation choice**: D.D1 reads more naturally in C4
   (Container view). We chose PlantUML component diagrams for
   uniformity across D.D1/D.D2/D.D3 — all three use the same
   subset renderer. If a future slice wants C4 specifically, add
   `core/diagrams/c4-render.ts` then.

4. **Multi-cloud edge derivation**: `InventoryEdge[]` currently
   captures within-cloud edges well (RDS → EC2, S3 → Lambda). Cross-
   cloud edges (AWS Lambda → GCP Pub/Sub) need operator-supplied
   `flowOverrides[]` until INV-S7 (cross-cloud edge discovery) ships.
   This is documented in the missing[] surface and is NOT a blocker.

5. **OSCAL back-matter wiring**: Adding
   `back-matter.resources[]` entries that link the SSP / AP / AR to
   the three SVGs is a small extension to `core/oscal-ssp.ts` /
   `oscal-ap.ts` / `oscal.ts` that LOOP-D does NOT cover in scope.
   It's a one-line follow-up after the diagrams ship; document as
   "post-LOOP-D wiring task" if not done in the same loop window.

6. **Boundary diagram for multi-CSO**: H.H3 (multi-CSO support)
   will partition `out/` per CSO. D.D1's `outDir` parameter already
   supports this; no additional refactor is required when H.H3
   lands.

7. **PlantUML jar version pinning**: When path (a) is enabled, log
   the jar version (`java -jar plantuml.jar -version`) into the
   diagram-manifest so reproducibility is auditable.

---

## 7. Status tracking

| Slice ID | Status | Commit | Completed date |
|---|---|---|---|
| D.D1 — Authorization Boundary Diagram | pending | — | — |
| D.D2 — Network Diagram | pending | — | — |
| D.D3 — Data Flow Diagram | pending | — | — |

Update this table when each slice ships (see §8).

---

## 8. Slice completion procedure (REO-enforced)

When a slice in LOOP-D ships, the implementer MUST:

1. **Run the full REO check locally**:
   ```bash
   cd cloud-evidence
   npm run typecheck && npm test && npm run check:reo
   ```
   All three commands must return 0.

2. **Update the Section 7 status table**: change the slice's row to
   `status=done`, `commit=<git rev-parse --short HEAD>`,
   `date=<ISO-8601 date>`. Commit this edit as part of the same slice
   commit.

3. **Add a CHANGELOG.md "Unreleased" entry** naming the slice + the
   module file paths + the verification counts. Pattern:
   ```
   ### Added — LOOP-D.D1: Authorization Boundary Diagram emitter
   <2-line summary citing what this closes>
     - `core/diagrams/boundary.ts`: <byte count> bytes, ...
     - `core/diagrams/plantuml-render.ts`: shared subset renderer ...
     - `core/orchestrator.ts`: `--abd` flag + env wiring ...
     - `core/submission-bundle.ts`: 4 new Role + WELL_KNOWN entries ...
     - `tests/core/diagrams/boundary.test.ts`: 14 tests ...

   Verification: typecheck clean; <N>/<N> tests passing (+46 from LOOP-D.D1);
   `npm run check:reo` returns 0.
   ```

4. **Update `cloud-evidence/docs/STATUS.md`** (or create it if
   absent) with the slice status flipped to `done` and the date.

5. **Commit** with the canonical message:
   ```
   LOOP-D.<slice-id>: <title>
   ```
   Example: `LOOP-D.D1: Authorization Boundary Diagram emitter`.

6. **Push** to `origin/main` (after CI passes locally via `npm run
   check:reo`).

7. **Verify** the CI workflow on the push run is green for the three
   guardrails (G1 + G2 + G3). If G3 (provenance) fails, the most
   likely cause is a missing `provenance` block on one of the three
   `*-diagram-manifest.json` files — fix and ship a new commit (do
   NOT amend).

---

## Appendix A — File-tree summary (what LOOP-D adds)

```
cloud-evidence/
├── core/
│   ├── diagrams/                              (new directory)
│   │   ├── boundary.ts                        (D.D1)
│   │   ├── network.ts                         (D.D2)
│   │   ├── dataflow.ts                        (D.D3)
│   │   ├── plantuml-render.ts                 (shared, lands in D.D1)
│   │   ├── svg-to-png.ts                      (shared, lands in D.D1)
│   │   └── diagram-manifest.ts                (shared, lands in D.D1)
│   ├── orchestrator.ts                        (extended × 3)
│   ├── submission-bundle.ts                   (extended × 3)
│   ├── sign.ts                                (extension: .puml/.svg/.png patterns)
│   └── inventory-coverage.ts                  (extension: boundary_tag + data_classification rows)
└── tests/
    └── core/
        └── diagrams/                          (new directory)
            ├── boundary.test.ts               (D.D1)
            ├── network.test.ts                (D.D2)
            ├── dataflow.test.ts               (D.D3)
            ├── plantuml-render.test.ts        (D.D1)
            ├── svg-to-png.test.ts             (D.D1, smoke only)
            └── diagram-manifest.test.ts       (D.D1)
```

Approximate net LOC added:
- Pure builders: ~500 lines × 3 = 1500 lines.
- Shared modules: ~600 lines (plantuml subset) + ~200 lines (svg-to-png) + ~150 lines (manifest writer) = ~950 lines.
- Tests: ~600 lines.
- Orchestrator + bundler + sign + coverage extensions: ~150 lines.

**Total: ~3200 lines of production + test code.**

---

## Appendix B — Tag schema operators must apply

LOOP-D consumes the following tag/label keys on cloud resources.
Operators apply these once (via Terraform / Pulumi / CloudFormation /
Bicep) and re-use them on every run. The tag scheme is the same as
INV-S6 (Diagram Label) extended with three new keys.

| Tag key | Values | Used by | REQUIRES-OPERATOR-INPUT triggered when |
|---|---|---|---|
| `fedramp_boundary` | `in` / `out` | D.D1, D.D3 | absent on every asset |
| `dataClassification` (also accepts `data_classification`, `fedramp_data_classification`) | `Public` / `Internal` / `CUI` / `PII` / `FOUO` / `<other>` | D.D3 | absent on an asset participating in an edge |
| `leveraged_service` | `<name>:<status>` (e.g. `Amazon-S3:fedramp-authorized`) | D.D1 | optional; operator override of leveragedServices[] |
| `external_entity` | `<entity-name>:<type>` (e.g. `USDA-Connect:agency`) | D.D3 | optional; operator override of externalEntities[] |
| `transport` | `TLS-1.3` / `TLS-1.2` / `mTLS` / `VPN-IPsec` / `VPN-Wireguard` | D.D3 | optional; falls back to openPorts derivation |
| `tls_version` | `1.2` / `1.3` | D.D3 | optional; refines TLS transport derivation |

The tag scheme is documented in
`cloud-evidence/docs/loops/LOOP-D-SPEC.md` (this file) AND surfaced
on every run via the orchestrator's
`requires_operator_input` diagnostic when missing.

---

## Appendix C — Quick reference: what each diagram answers

| Question a 3PAO asks | Answered by |
|---|---|
| "What's in scope for this authorization?" | D.D1 (Authorization Boundary Diagram) |
| "Which external systems does the CSO connect to?" | D.D1 (leveraged-service edges) |
| "What's the FedRAMP authorization status of every connected service?" | D.D1 (status label per leveraged-service cloud node) |
| "How is the network segmented? Where is the DMZ?" | D.D2 (Network Diagram — subnet labels public/private) |
| "Which subnets allow inbound 0.0.0.0/0?" | D.D2 (firewall rule summary) |
| "Where does PII flow within the system?" | D.D3 (Data Flow Diagram — labelled flows) |
| "Is encrypted-in-transit enforced on every flow?" | D.D3 (transport labels on every arrow) |
| "Does the data flow ever leave the boundary?" | D.D3 (flows crossing trust-boundary doubled arrows) |

---

*End of LOOP-D-SPEC.md. Implementer next step: open
`cloud-evidence/CLAUDE.md`, then this file, then say
`continue with LOOP-D.D1`.*
