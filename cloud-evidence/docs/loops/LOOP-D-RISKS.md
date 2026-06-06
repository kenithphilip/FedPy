# LOOP-D — Risks Register

> Live document. Implementing sessions add entries during work; resolved
> risks stay in the file with `status=resolved` + resolution note +
> commit hash. The register feeds the per-slice "Known risks / issues"
> sections and the loop-wide acceptance review.

Last updated: 2026-06-06

---

## Cross-cutting risks (apply to ALL slices in this loop)

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| **CX-D-1** | high | PlantUML subset renderer LOC budget is the single biggest piece of work in LOOP-D. The shared `core/diagrams/plantuml-render.ts` must support every shape D.D1 / D.D2 / D.D3 emit (package, component, cloud, node, frame, database, actor, usecase, note, legend, labelled arrows including doubled `==>`, color-decorated `-[#color,bold]->`). ~600 LOC. If the budget slips, D.D2/D.D3 are blocked. | (1) Ship the minimum subset D.D1 needs first; D.D2/D.D3 extend as their shapes appear. (2) Path (a) `plantuml.jar` fast-path is documented as the canonical reference renderer — the pure-TS subset is for CI/dep-free runs. (3) Grammar coverage is tracked in the source file's header comment so adding a shape is a documented surface, not a hidden change. | open |
| **CX-D-2** | high | Layout quality. A pure-TS layout engine produces visibly inferior diagrams compared to Graphviz. 3PAOs may file findings about diagram readability. | (1) Title + legend + grouping carry the substantive content; layout aesthetics are secondary to determinism + REO traceability. (2) When `plantuml.jar` is on the machine, the renderer auto-detects and uses it (Graphviz layout). (3) `LOOP-D-SPEC.md` Section 6 documents the choice + escalation path (add Graphviz dep, build C4 renderer) for future loops. | open |
| **CX-D-3** | high | PNG generation in pure JS is non-trivial. Rasterising SVG without a headless browser requires either `sharp` (a binary dep with ~5MB platform-specific binary) or a hand-rolled SVG-subset rasterizer. | (1) Ship `sharp` opt-in detection first (`require.resolve('sharp')` defensively) with a typed warning when absent. (2) SVG is the canonical output; PNG is convenience. (3) Pure-TS PNG implementation is a follow-up the spec allows to be omitted if it exceeds timebox; CHANGELOG entry must call out which path is shipped. | open |
| **CX-D-4** | med | `core/sign.ts` extension allow-list change (`.puml`, `.svg`, `.png`, `.diagram-manifest.json`) could destabilise existing signed-artifact tests. | (1) Extend the allow-list as a single Edit; (2) re-run `tests/core/sign.test.ts` before any diagram emit lands; (3) the allow-list extension goes in with D.D1 and is reused by D.D2 / D.D3 unchanged. | open |
| **CX-D-5** | med | `submission-bundle.ts` `WELL_KNOWN[]` catalogue grows by 9 entries (3 diagrams × 3 formats) + 1 manifest pattern. A typo in any filename means a diagram silently ships outside the bundle. | (1) Each WELL_KNOWN entry has a corresponding test in `tests/core/submission-bundle.test.ts` asserting role-classification. (2) The `diagram-manifest` role uses a regex `/^(boundary|network|dataflow)-diagram-manifest\.json$/` so the three manifests classify uniformly. | open |
| **CX-D-6** | med | Determinism across runs requires a stable clock. The title block "generated <ISO-date>" cannot be wall-clock UTC, or the determinism tests fail. | (1) Builder accepts a clock parameter; (2) orchestrator passes the run-ledger's `runId` timestamp (already ISO-8601 in the existing run-lock infrastructure); (3) every slice's determinism test (#10 in D.D1, #14 in D.D2, #13 in D.D3) seeds the same `runId` and asserts byte-equality. | open |
| **CX-D-7** | med | All three diagrams depend on `out/inventory.json` being current. If the orchestrator's `--inventory` step has not run in the same invocation OR a stale `out/inventory.json` is on disk, the diagrams are emitted against stale data. | (1) Every emitter calls `readPreviousInventory()` which carries the snapshot's emitted-at timestamp; (2) when the snapshot is older than 24 hours, emit a `stale_inventory` warning in the manifest's `provenance` block; (3) orchestrator's `--abd` / `--network-diagram` / `--dfd` flags imply `--inventory` (auto-run) unless `--no-inventory` is passed. | open |
| **CX-D-8** | med | Three different diagram types emit to the same `outDir`. Naming collisions are possible if a future slice adds e.g. `boundary.json` (clashing with `boundary-diagram-manifest.json` as a substring). | (1) Manifest filenames use the `-diagram-manifest.json` suffix to be unmistakable. (2) Bundler classification uses exact-match filenames where possible, regex only for the manifest. (3) Submission-bundle tests assert no overlap between role classifications. | open |
| **CX-D-9** | med | The shared `diagram-manifest.ts` schema version is `1.0.0`. Any breaking change (renaming a top-level field, changing a node-source enum) would invalidate manifests from older runs that downstream consumers (LOOP-G.G4, LOOP-E.E6) may still reference. | (1) Bump `version: '1.0.0'` field on any breaking change. (2) Add a test asserting all three diagrams use the same version. (3) Document a "minor version" vs "major version" rule in the manifest schema header comment. | open |
| **CX-D-10** | low | `fedramp_boundary` tag accepts case-insensitive aliases (`fedramp_boundary`, `fedramp-boundary`, `boundary`). Substring matching could accidentally match unrelated keys like `boundary_account_id`. | Use exact set membership against the three accepted keys, not substring match. Test the negative case (key `boundary_account_id` must NOT trigger the tag handler). | open |
| **CX-D-11** | low | Operator-supplied YAML files (`--flow-overrides`, `--external-entities`) parsed at orchestrator boot can crash the run with an unhelpful error if malformed. | Use the same YAML loader pattern as `core/risk-config.ts` (B.B1) which surfaces parse errors with file path + line number; never silently accept partial config. | open |
| **CX-D-12** | low | The `plantuml.jar` fast-path is gated on `which java` AND `which plantuml`. On macOS Apple Silicon, Homebrew installs to `/opt/homebrew/Cellar/plantuml/*/libexec/plantuml.jar` — a glob path. The detector must handle the glob. | (1) Detection order: `$CLOUD_EVIDENCE_PLANTUML_JAR` env → `which plantuml` → `/usr/local/lib/plantuml.jar` → `/opt/homebrew/Cellar/plantuml/*/libexec/plantuml.jar` (resolved via `fs.readdirSync` over the Cellar dir). (2) Log the resolved jar version into the manifest's provenance block. | open |
| **CX-D-13** | low | Diagram outputs are not directly OSCAL-referenced. Adding `back-matter.resources[]` entries to SSP / AP / AR for the three SVGs is documented as a post-LOOP-D follow-up in `LOOP-D-SPEC.md` §6. If the follow-up is forgotten, the OSCAL submission ships without the embedded references. | (1) `LOOP-D-SPEC.md` §6 explicitly tracks this as a follow-up task; (2) the submission-bundle catalogue still includes the SVGs (so they're physically in the .tar.gz); (3) a post-LOOP-D task is filed in `cloud-evidence/docs/EXECUTION-PLAN.md` as a one-line extension to `core/oscal-ssp.ts` / `oscal-ap.ts` / `oscal.ts`. | open |
| **CX-D-14** | low | The three diagrams together can add ~6 MB to the submission bundle (3 PNGs at ~300KB + 3 SVGs at ~150KB + 3 manifests at ~5KB + 3 PUMLs at ~10KB ≈ ~1.4MB, plus signing manifest entries). | (1) `--diagram-format=puml-only` reduces footprint to ~30KB total; (2) the bundle currently ships at ~6 MB so a 25% increase is acceptable; (3) document in RUNBOOK.md the format selector for size-constrained transports. | open |

---

## Per-slice risks (not duplicated from cross-cutting)

### D.D1 — Authorization Boundary Diagram

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| D1-1 | high | `leveragedServices[]` programmatic input vs tag-derived input can disagree (operator passes `--leveraged-service Amazon-S3:fedramp-authorized` AND tags an asset `leveraged_service=Amazon-S3:csp-managed-shared`). | Programmatic wins; tag-derived entries are merged AFTER programmatic, so programmatic takes precedence on `name` collision. Manifest records both sources in `synthesized_fields[]`. Test #5 covers this. | open |
| D1-2 | med | Boundary classification ambiguity: an asset can be in-boundary (CSP-operated) but its data flows OUTSIDE the boundary (to an agency tenant). The diagram needs to show both the asset AND the flow. | The asset renders inside the `package "Authorization Boundary"` AND its outbound flow is a crossing arrow. The data-classification label on the arrow tells the 3PAO what type of data crosses. | open |
| D1-3 | med | An asset with `fedramp_boundary=in` but no edges (orphan asset) renders inside the boundary but unconnected. 3PAOs may flag as "what is this for?". | Group label includes the count suffix `(n=<count>)` so the unconnected asset still appears in its group; manifest cites the asset's `uniqueId`. Operator can add a `note` via Comments tag (INV-S6) if context is needed. | open |
| D1-4 | low | The legend pane bottom-right could overlap the boundary package if PlantUML layout is constrained. | (1) The pure-TS subset renderer pre-computes width budget for the legend; (2) `plantuml.jar` fast-path uses Graphviz layout which handles overlap automatically; (3) test #1 visually inspects the SVG dimensions. | open |
| D1-5 | low | An asset's `assetType` could be inconsistent across providers (`ec2` vs `compute` vs `vm`). Grouping by `(provider, assetType)` then produces too many groups. | Inventory normalizes `assetType` already (INV-P1); D.D1 reads the normalized value. If normalization fails, the group label shows the raw value; tests assert normalization for the standard types. | open |

### D.D2 — Network Diagram

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| D2-1 | high | Large security-group rule counts (some AWS accounts have 500+ rules per SG) produce unreadable rule-summary notes. | `firewallRuleSummaryLimit` default 5 limits each direction. Full rule set still cited in `manifest.firewall_rules[]` for audit. Diagram is a summary; manifest is the source of truth. | open |
| D2-2 | high | Network ACLs are NOT in scope for the rule summary (only security-groups). A 3PAO may ask "where are the NACLs?". | Manifest's `summary_scope` field explicitly lists what IS and is NOT in the summary. NACL summary is filed as a follow-up; the SC-7 proof still holds because SGs are the per-instance enforcement layer. | open |
| D2-3 | med | Subnet public/private classification depends on route-table analysis the inventory snapshot may not have run on every subnet (INV-P2 best-effort). | When route table not collected, render label as `subnet-id · <cidr> · class-unknown REQUIRES-OPERATOR-INPUT` and add to missing[]. Never default to `public` or `private`. | open |
| D2-4 | med | Cross-account peering edges only appear when both accounts are in the org-fan-out scan (INV-P3). Single-account runs miss the other end. | When an edge has only one endpoint resolvable in the snapshot, render with `note: peer-vpc-uniqueId not in inventory; cross-account scan required` and a missing[] entry. | open |
| D2-5 | low | GCP "default" network — a Network named `default` is auto-created on every project. Including it clutters layout. | Render it; add a manifest synthesized field `'note:gcp-default-network-auto-created'` so a reviewer knows the CSP did NOT explicitly create it. | open |
| D2-6 | low | Azure VNet peering can be one-way (initiator vs accepter). | Render as bidirectional arrow unless peering state shows `Initiated` (one-way) — then render `-->` with label `one-way: <initiator> → <accepter>`. | open |
| D2-7 | low | AWS Network Firewall (`Microsoft.Network/azureFirewalls` Azure analog) is a different resource type from SG/NSG. | Out of scope for the summary in v1 — note as follow-up; manifest's `summary_scope` lists what's covered. | open |
| D2-8 | low | Multi-NIC VMs / ENI attachments mean an asset can live in multiple subnets. The diagram needs a primary subnet for placement. | Render in primary subnet (first ENI by attachment order); add `note: also-in <other-subnet-id>` for each additional. Manifest cites all subnet memberships. | open |

### D.D3 — Data Flow Diagram

| ID | Severity | Description | Mitigation | Status |
|---|---|---|---|---|
| D3-1 | high | `dataClassification` tags are operator-supplied and frequently absent at the start of a FedRAMP authorization. The diagram WILL render with many `UNCLASSIFIED` labels. | The `missing[]` surface + coverage drop + run-log `coverage:miss` lines guide the operator. Tag scheme documented in LOOP-D-SPEC Appendix B. | open |
| D3-2 | high | Cross-cloud edges (AWS Lambda → GCP Pub/Sub) are NOT captured by `InventoryEdge[]` until INV-S7 ships. | Operator supplies cross-cloud flows via `--flow-overrides=<path>`. When `externalEntities[]` includes `type=external-system` AND no override connects to it, emit disconnected `actor` + missing[] entry pointing to `--flow-overrides`. | open |
| D3-3 | med | Classification taxonomy (Public/Internal/CUI/PII/FOUO/Other) is opinionated. Operators with org-specific labels use `Other` and lose standard mapping. | `Other` preserves verbatim operator string; manifest records both the original tag value AND the taxonomy mapping. Future slice can extend the enum. | open |
| D3-4 | med | PII detection is tag-based, not content-based. A bucket actually containing PII but not tagged renders as `UNCLASSIFIED` or `Public`. | By design (REO standard rules out content-introspection). Operator's data-classification process is the source of truth. Source-file header documents this explicitly. | open |
| D3-5 | med | Trust-boundary rendering depends on D.D1's `fedramp_boundary` tag. If D.D1 has not been run / tag is missing, the trust-boundary `package` collapses. | D.D3 lists D.D1 in `depends_on:` so the spec's ordering encourages tagging first. Diagram still emits — just without boundary visualization (with explicit missing[] entry). | open |
| D3-6 | med | `flowOverrides[]` can declare a flow whose endpoints don't exist in inventory (orphaned override). | Emit `manifest.flow_override_orphans[]` with offending entries AND a missing[] entry; diagram still renders the override (operator deliberately added it). | open |
| D3-7 | low | External-entity tag value parsing (`<name>:<type>`) is brittle if the entity name contains a colon. | Tag value parser splits on the LAST `:` not the first; tests cover the edge case. | open |
| D3-8 | low | PlantUML `actor` + `usecase` + `database` in a single diagram can produce odd layout. | Layout is secondary to content; PlantUML jar fast-path uses Graphviz. Pure-TS subset renderer's layout is documented as "best-effort". | open |
| D3-9 | low | The shared `buildDataFlowGraph()` export creates a public API LOOP-G.G4 depends on. A breaking change would cascade. | Lock the `DfdGraph` type signature with a comment marking it as "public API — LOOP-G.G4 dependency"; bump the diagram-manifest version on any breaking change; add a contract test in D.D3 that asserts the export shape. | open |
| D3-10 | low | Intra-process flows (ECS task → ECS task same service) are noise on the diagram. | Filter intra-process flows where both endpoints in same `(provider, assetType, application-tag)` group; report count in `manifest.intra_process_filtered_count`. | open |

---

## External dependencies that may change

| Dependency | Current pinned version / behaviour | Risk if it changes | Action |
|---|---|---|---|
| **FedRAMP Authorization Boundary Guidance** PDF | Latest published version as of 2026-06-06 (URL: `https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf`) | New "Required Elements" added → ABD may be incomplete | Implementer downloads PDF before each LOOP-D slice ship; required-elements checklist re-verified; ABD test #2 updated if new elements added. |
| **NIST SP 800-53 Rev5** (patch release 5.1.1) | SC-7, AC-4, CA-3, PL-2, SC-8, SC-13 control statements quoted verbatim from `NIST.SP.800-53r5.pdf` | Rev6 issues new control text → quotes go stale | Track the NIST CPRT catalog publication date in the source file headers; on Rev6 publication, refresh quotes + diff the control text. |
| **NIST SP 800-53A Rev5** (assessment procedures, currently Rev5.2.0 with 5.3.0 in draft) | LOOP-D doesn't directly depend on 800-53A, but downstream LOOP-F.F7 (SAR) does | Indirect — assessment criteria for SC-7/AC-4 evidence may change | LOOP-D outputs are agnostic; LOOP-F.F7's SAR text consumes the diagrams as-is. No LOOP-D change required. |
| **PlantUML version** | Latest stable (1.2024.0+) when `plantuml.jar` is available; pure-TS subset renderer otherwise | New shape syntax added; existing shape rendering changes | Pure-TS subset is the canonical renderer for deterministic CI; jar fast-path's version is logged into manifest. Test #5 in `plantuml-render.test.ts` gates jar fast-path on `which java`. |
| **`sharp` npm package** (optional dep) | Detected via `require.resolve('sharp')`; not in package.json | New major version changes API | Defensive `try { require.resolve('sharp') } catch { fallback }` pattern means version churn doesn't break the build. |
| **OSCAL v1.1.2** (SSP / AP / AR back-matter) | `https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/` | v1.2.0+ may rename `back-matter.resources[]` or `media-type` field | LOOP-D doesn't write OSCAL directly; the post-LOOP-D follow-up (back-matter wiring) is in LOOP-A's spec doc. If OSCAL bumps, follow-up adapts. |
| **FedRAMP 20x RFC-0024** (OSCAL submission RFC) | Current published version | Diagram embed mechanism may change (e.g. base64-inline vs href reference) | LOOP-D ships .svg as href reference; if RFC mandates base64 inline, add to SSP-2 .docx embedder. |
| **CISA BOD 22-01 KEV catalog** | Referenced for D.D1's downstream LOOP-B.B2 KEV branch | New KEV entries change deadlines, not diagram content | LOOP-D doesn't read KEV; no action. |
| **Yourdon / DeMarco DFD notation** | 1979/1989 (stable) | None expected | No action. |
| **RFC 1918 / RFC 6598** (private address ranges) | Stable | None expected | No action. |
| **RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2)** | Stable | New TLS RFC (e.g. 1.4) | Add to transport taxonomy when published. |
| **FIPS 140-3** | Current revision | FIPS 140-4 in development | Transport label taxonomy adds FIPS-140-4 distinction when published. |
| **AWS / GCP / Azure SDK resource type names** | Current SDK versions in `cloud-evidence/package.json` | Resource type rename (rare) | Inventory normalization layer (INV-P1) shields D.D2 / D.D3 from SDK churn. |
| **Cargo / Homebrew install paths for `plantuml`** | `/opt/homebrew/Cellar/plantuml/*/libexec/plantuml.jar` on Apple Silicon | Homebrew formula path change | Detector uses glob + readdir, not hardcoded version. |
| **NIST CUI Registry** | `https://www.archives.gov/cui/registry/category-list` | New category list | Classification taxonomy adds new entries via tag value `Other`; no LOOP-D code change required. |

---

## Resolved risks (historical)

(empty initially — populated as risks are resolved during slice
implementation. Each resolved entry MUST include: ID, resolution
commit hash, resolution note, date resolved, resolver session-id.)

Format:

```
| ID | Resolution commit | Resolution note | Date | Resolver |
|---|---|---|---|---|
| CX-D-N | <hash> | <1-2 line description of how the risk was mitigated in code> | YYYY-MM-DD | (session id) |
```

---

## Schema for adding new risks

When an implementing session discovers a new risk:

1. Pick the next available ID: `CX-D-<n>` for cross-cutting,
   `D1-<n>` / `D2-<n>` / `D3-<n>` for per-slice.
2. Severity: `high` (blocks slice ship), `med` (fix-on-followup
   acceptable with documented compensating control), `low` (cosmetic
   or rare-edge).
3. Status: `open` (active), `mitigated` (compensating control in
   place but not fully fixed), `resolved` (fix shipped + commit hash
   recorded).
4. Mitigation MUST cite either a specific commit or a specific code
   path / test. Hand-wave mitigations are REO violations.
5. When resolving, MOVE the row from the per-section table to the
   "Resolved risks (historical)" table with the resolution commit
   + date.

---

## Cross-references

- **Per-slice details**: `docs/slices/D/D.D1.md`,
  `docs/slices/D/D.D2.md`, `docs/slices/D/D.D3.md` — each carries a
  slice-specific "Known risks / issues" section that mirrors the
  per-slice entries above.
- **Loop spec**: `docs/loops/LOOP-D-SPEC.md` Section 6 (Open
  questions / caveats) is the authoritative narrative for caveats;
  this risks register is the table form.
- **REO standard**: `cloud-evidence/CLAUDE.md` — every mitigation
  cited here MUST satisfy the REO Real Slice Contract.
- **Execution plan**: `docs/EXECUTION-PLAN.md` — high-level plan
  with all 55 slices; LOOP-D's three slices are listed there.
- **Status tracker**: `docs/STATUS.md` — slice-level done/pending
  status; this risks register is independent (risks can be open
  while slices are done).

---

(end of LOOP-D-RISKS.md)
