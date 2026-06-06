---
slice_id: D.D2
title: Network Diagram (ND) emitter
loop: D
status: pending
commit: —
completed_date: —
depends_on: [INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, INV-S2, INV-S3, INV-S6, REO-0, LOOP-A.A4, D.D1]
blocks: [D.D3, LOOP-C.C9, LOOP-E.E6, LOOP-G.G4, LOOP-F.F4]
estimated_effort: 3–4 days
last_updated: 2026-06-06
---

# D.D2 — Network Diagram (ND) emitter

## TL;DR
Generates a deterministic Network Diagram (`network.puml` + `network.svg` +
`network.png` + `network-diagram-manifest.json`) directly from
`out/inventory.json` VPC / VNet / VPC-network discovery plus subnet, route,
peering, transit-gateway, and security-group / NSG / firewall-rule context
already collected by INV-P2/S2/S3. Reuses the three shared diagram modules
(`plantuml-render.ts`, `svg-to-png.ts`, `diagram-manifest.ts`) D.D1 lands.
Closes SSP §9.2 "Network Architecture" gap with byte-stable output and is
the primary visual a 3PAO uses to map SC-7 (Boundary Protection) +
SC-7(3/4/5) sub-controls to actual firewall posture.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Why this slice exists
SSP §9.2 ("Network Architecture") in the FedRAMP Moderate SSP template
requires a current diagram showing every VPC / VNet / VPC-network in scope
with subnets labelled (CIDR + public/private), route-table summaries,
edge devices (IGW / NAT / VPC endpoints / Cloud NAT), peering / transit-
gateway relationships, and a firewall-rule summary at the edge.

Today every CSP draws this in Visio / Lucidchart and the diagram diverges
from the running cloud the moment a subnet is added, a route is changed,
or a security-group rule is updated. The Network Diagram is also the
single most cited artifact in 3PAO findings for SC-7-family controls
because it's the only place a reviewer can see "how is this network
actually segmented?" without re-reading raw Terraform.

D.D2 closes that gap by reading the existing INV-P2 VPC / Subnet / Route /
Peering / Security-Group / Firewall enumeration from `out/inventory.json`
and emitting a deterministic deployment diagram. Operator misses (orphan
subnet, 0.0.0.0/0 rule on a private subnet) surface as
`REQUIRES-OPERATOR-INPUT` markers in the diagram itself.

This slice does NOT add any new collector. It is a presentation layer over
data INV-P2/S2/S3 already collect.

## Authoritative sources (with verbatim quotes)

### S1 — NIST SP 800-53 Rev5 §3.20 SC-7 (Boundary Protection) + SC-7(3/4/5)
URL: `https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf`
(Rev5 with patch release 5.1.1, SC family appendix.)

SC-7 base control:
> "Monitor and control communications at the external managed interfaces
> to the system and at key internal managed interfaces within the system;
> implement subnetworks for publicly accessible system components that
> are physically or logically separated from internal organizational
> networks; and connect to external networks or systems only through
> managed interfaces consisting of boundary protection devices arranged
> in accordance with an organizational security and privacy
> architecture."

SC-7(3) Access Points:
> "Limit the number of external network connections to the system."

SC-7(4) External Telecommunications Services:
> "Implement a managed interface for each external telecommunications
> service; establish a traffic flow policy for each managed interface;
> protect the confidentiality and integrity of the information being
> transmitted across each interface; document each exception to the
> traffic flow policy with a supporting mission or business need and
> the duration of that need; review exceptions to the traffic flow
> policy [at organization-defined frequency]; and remove exceptions
> that are no longer supported by an explicit mission or business need."

SC-7(5) Deny by Default — Allow by Exception:
> "Deny network communications traffic by default and allow network
> communications traffic by exception at managed interfaces."

The Network Diagram is the visual proof for all four control statements:
the subnet-per-tier rendering proves SC-7's "subnetworks separation"
clause; the IGW / NAT / VPC-endpoint nodes prove SC-7(3) "limit external
connections"; the firewall-rule summary proves SC-7(4) "traffic-flow
policy per managed interface" and SC-7(5) "deny by default".

### S2 — FedRAMP Authorization Boundary Guidance, Network Architecture section
URL: `https://www.fedramp.gov/assets/resources/documents/CSP_A_FedRAMP_Authorization_Boundary_Guidance.pdf`
The guidance enumerates what must be visible on the Network Diagram:
IGW, NAT gateway, peering, transit-gateway, VPN tunnels, public subnets,
private subnets, the AWS / Azure / GCP region layer, and the "boundary
crosses the diagram" demarcation. (The implementer MUST download the PDF
and confirm the verbatim "Network Architecture" subsection before
shipping.)

### S3 — PlantUML Deployment Diagram syntax reference
URL: `https://plantuml.com/deployment-diagram`
Key tokens this slice emits:
- `@startuml ... @enduml` document wrappers.
- `title ...` multi-line title.
- `cloud "AWS / <region>" as awsR1 { ... }` for cloud-region container.
- `node "VPC <id> · <cidr>" as vpcA { ... }` for VPC nodes.
- `frame "subnet <id> · <cidr> · public" as subA1` for subnet rectangles
  inside a VPC.
- `database "RDS-<id>" as db1` for stateful nodes inside a subnet.
- `node "IGW <id>" as igw1`, `node "NAT <id>" as nat1` for edge devices.
- `vpcA --[#blue,bold]-> tgwHub : "rfc1918 east-west"` for labelled
  peering / TGW arrows.
- `note right of vpcA` for firewall rule summaries.

### S4 — AWS VPC resource enumeration
URL: `https://docs.aws.amazon.com/vpc/latest/userguide/`
Resource types this slice reads (already collected by
`providers/aws/network.ts`):
- `Vpc` (CIDR block, region).
- `Subnet` (CIDR, AZ, map-public-ip-on-launch).
- `RouteTable` + `Route` (destination CIDR + target IGW/NAT/peering).
- `InternetGateway` (attached VPC).
- `NatGateway` (subnet, public IP).
- `VpcEndpoint` (service name + interface/gateway).
- `VpcPeeringConnection` (accepter VPC + requester VPC + status).
- `TransitGateway` + `TransitGatewayVpcAttachment`.
- `SecurityGroup` (rules: from/to port, CIDR, protocol, direction).
- `NetworkAcl` (numbered rules, allow/deny).

### S5 — Azure VNet resource enumeration
URL: `https://learn.microsoft.com/en-us/azure/virtual-network/`
Resource types (already in `providers/azure/network.ts`):
- `Microsoft.Network/virtualNetworks` (addressSpace.addressPrefixes).
- `Microsoft.Network/virtualNetworks/subnets` (addressPrefix).
- `Microsoft.Network/routeTables` + `routes`.
- `Microsoft.Network/networkSecurityGroups` (securityRules).
- `Microsoft.Network/virtualNetworkPeerings`.
- `Microsoft.Network/azureFirewalls` (firewall policies).

### S6 — GCP VPC resource enumeration
URL: `https://cloud.google.com/vpc/docs/vpc`
Resource types (already in `providers/gcp/network.ts`):
- `compute.googleapis.com/Network` (auto-create vs custom).
- `compute.googleapis.com/Subnetwork` (ipCidrRange, region, privateGoogleAccess).
- `compute.googleapis.com/Route` (destRange, nextHop*).
- `compute.googleapis.com/Firewall` (sourceRanges, allowed, denied, priority).
- `compute.googleapis.com/Router` + `compute.googleapis.com/RouterNat`.
- `compute.googleapis.com/InterconnectAttachment`.

### S7 — RFC 1918 / RFC 6598 (private address ranges)
URL: `https://datatracker.ietf.org/doc/html/rfc1918` /
`https://datatracker.ietf.org/doc/html/rfc6598`
> "The Internet Assigned Numbers Authority (IANA) has reserved the
> following three blocks of the IP address space for private internets:
> 10.0.0.0 — 10.255.255.255 (10/8 prefix); 172.16.0.0 — 172.31.255.255
> (172.16/12 prefix); 192.168.0.0 — 192.168.255.255 (192.168/16 prefix)."
Used to classify subnets as `private` (RFC1918 or RFC6598 CIDR) vs
`public` (any other) before consulting the `mapPublicIpOnLaunch` flag.

### S8 — RFC 3161 (Time-Stamp Protocol)
URL: `https://datatracker.ietf.org/doc/html/rfc3161`
The signed manifest covers `.puml`/`.svg`/`.png`/`.diagram-manifest.json`
under the allow-list D.D1 already extended.

### S9 — FedRAMP Continuous Monitoring Performance Management Guide
URL: `https://www.fedramp.gov/assets/resources/documents/CSP_Continuous_Monitoring_Performance_Management_Guide.pdf`
ConMon-required visualizations include the up-to-date network diagram on
every SCN; the spec mandates the diagram be re-emitted on every
significant change.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/diagrams/network.ts` — pure builder
  (`buildNetworkPuml`) + disk emitter (`emitNetworkDiagram`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/diagrams/network.test.ts` —
  ~14 tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-network-min.json` —
  small AWS-only VPC + 2 subnets + 1 IGW + 1 NAT + 1 SG fixture for unit
  tests.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/inventory-network-multicloud.json` —
  AWS + GCP + Azure mixed fixture with peering edges + rule summaries.

## Files to extend
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`:
  add CLI flag `--network-diagram` + env `CLOUD_EVIDENCE_NETWORK_DIAGRAM=1`.
  When `--abd` also set, ND runs AFTER ABD (same point in pipeline:
  after `applyDiagramLabelAndComments`, before `signEvidence()`).
  Console log: `ND: regions=<r> vpcs=<v> subnets=<s> peerings=<p> rule-summaries=<rs>`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`:
  extend `Role` union with `'network-diagram-puml'`,
  `'network-diagram-svg'`, `'network-diagram-png'`. Append three
  `WELL_KNOWN[]` entries:
  - `{ role: 'network-diagram-puml', filename: 'network.puml', description: 'Network Diagram — PlantUML source' }`
  - `{ role: 'network-diagram-svg', filename: 'network.svg', description: 'Network Diagram — SVG render' }`
  - `{ role: 'network-diagram-png', filename: 'network.png', description: 'Network Diagram — PNG render' }`
  (The `diagram-manifest` role from D.D1 already matches
  `/^(boundary|network|dataflow)-diagram-manifest\.json$/` so the
  network manifest classifies correctly.)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`:
  no new column. ND consumes existing `vlan_network_id` (column U),
  `ip_address` (column C), and `public` (column D) coverage rows.

## Schemas / standards
- **PlantUML deployment-diagram subset** (see S3 above): `cloud`,
  `node`, `frame`, `database`, labelled `-->` and `==>` arrows, `note`,
  `title`. All within the subset the D.D1 `plantuml-render.ts` already
  supports — this slice extends the subset ONLY if a needed shape is
  missing (document the addition in the shared module's grammar header
  comment).
- **CIDR classification rules**:
  - RFC1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
  - RFC6598 range: `100.64.0.0/10` (CGN).
  - Private if subnet CIDR falls inside any of the above AND
    `mapPublicIpOnLaunch === false` (AWS) / no IGW route (any cloud).
  - Public otherwise.
- **Edge-type taxonomy** (consumed from `InventoryEdge.type`):
  - `peering` — VPC-to-VPC.
  - `tgw-attachment` — VPC-to-TGW.
  - `vpn` — VPC-to-VPN tunnel.
  - `interconnect` — VPC-to-Direct-Connect / Interconnect / ExpressRoute.
  - `cross-region` — inferred when from.region !== to.region.
- **Firewall rule summary schema** (per VPC `note right of` body):
  - `direction`: `ingress` / `egress`.
  - `protocol`: `tcp` / `udp` / `icmp` / `all`.
  - `port_range`: `<from>-<to>` or `all`.
  - `source` / `destination`: CIDR or named security-group reference.
  - `action`: `allow` / `deny`.
  - Sort: most-permissive first (broadest CIDR, widest port range).
  - Limit: `firewallRuleSummaryLimit` (default 5 per direction).
- **JSON manifest schema** identical to D.D1's, with `diagram_kind: 'network'`.

## Build steps (concrete, numbered)
1. **Interfaces in `core/diagrams/network.ts`** (mirror LOOP-D-SPEC §4
   D.D2):
   ```ts
   export interface NetworkDiagramOptions {
     outDir: string;
     runId: string;
     firewallRuleSummaryLimit?: number; // default 5
     formats?: Array<'puml' | 'svg' | 'png'>;
     providers?: Array<'aws' | 'gcp' | 'azure'>; // restrict scope
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
2. **Pure builder** `buildNetworkPuml(snapshot, opts)`:
   - Group `snapshot.assets[]` by `(provider, location)` — one
     `cloud "<Provider> / <region>"` per group.
   - Inside each region, filter assets by `resourceType` matching one of
     the VPC / VNet / network types listed in S4/S5/S6. Emit one `node`
     per VPC.
   - Inside each VPC node, filter subnets by `vlanNetworkId`/parent VPC
     and emit one `frame` per subnet, label
     `<subnet-id> · <cidr> · <public|private>`.
   - Inside each subnet, place `database` nodes for any DB asset
     (`assetType` matches `/rds|sql|cosmos|firestore|dynamodb/i`) in
     that subnet.
   - Edges: iterate `snapshot.edges[]` filtered by
     `type ∈ {peering, tgw-attachment, vpn, interconnect}` and emit a
     labelled arrow `<from-alias> --[#blue,bold]-> <to-alias> : "<type>"`.
   - Cross-region edges: emit doubled arrows `==>` with label
     `"cross-region <from-region>→<to-region>"`.
   - Firewall rule summary: for each VPC node, find security-groups /
     NSGs / firewalls attached to it (via
     `asset.tags['security_group_id']` or analogous). Sort rules by
     CIDR-size (broadest first) then port-range (widest first). Emit a
     `note right of <vpc-alias>` with the top
     `firewallRuleSummaryLimit` per direction.
   - Title: `title Network Diagram\nrunId=<id> · generated <ISO-date>`.
   - REQUIRES-OPERATOR-INPUT triggers (see §"REQUIRES-OPERATOR-INPUT"
     below) surface as inline notes + missing[] entries.
3. **Disk emitter** `emitNetworkDiagram(opts)`:
   - Read `out/inventory.json` via the
     `core/inventory-emit.ts:readPreviousInventory()` pattern; if
     absent, throw `MissingInventoryError` (same error type D.D1
     defined).
   - Run `buildNetworkPuml`.
   - Write `<outDir>/network.puml` (always).
   - If `formats` includes `svg`: call shared
     `renderPumlToSvg(puml, opts)`.
   - If `formats` includes `png`: call shared
     `svgToPng(svg, { width: 1600 })`.
   - Write `<outDir>/network-diagram-manifest.json` enumerating every
     node + every edge + every firewall rule cited.
4. **Wire to orchestrator** `core/orchestrator.ts`:
   - Flag `--network-diagram`, env `CLOUD_EVIDENCE_NETWORK_DIAGRAM=1`.
   - Inherit `--diagram-format` selector from D.D1 (no new flag).
   - Inherit `--providers=aws,gcp,azure` if D.D2 needs to restrict
     scope.
   - Runs at the same pipeline point as D.D1 (after S6, before sign).
5. **Submission bundler** `core/submission-bundle.ts`: extend Role +
   WELL_KNOWN as documented in Files-to-extend.
6. **Validation pass**: Each rule in the firewall summary MUST cite a
   real `SecurityGroup` / `NSG` / `Firewall` resource in the manifest
   (cite `asset.uniqueId` + `ruleIndex`). Validate via ajv against the
   manifest schema.
7. **Signing + timestamp**: covered automatically by D.D1's `core/sign.ts`
   allow-list extension.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (CLAUDE.md): every field that cannot be auto-derived
emits a marker that names the field, consumer, and remediation hint.

| Field | Source | What happens when missing |
|---|---|---|
| Subnet CIDR | `asset.tags.cidr` / native `addressPrefix` / `ipCidrRange` from cloud SDK | Subnet rendered with label `CIDR: REQUIRES-OPERATOR-INPUT`; `missing[]` += `subnet-cidr:<subnet-uniqueId>` |
| Subnet parent VPC | derived from `asset.vlanNetworkId` field | Orphan subnet (no parent VPC in `assets[]`): rendered as a standalone `frame` outside any VPC `node` with `note bottom: REQUIRES-OPERATOR-INPUT — parent VPC not in inventory; verify INV-P2 collected it`; `missing[]` += `orphan-subnet:<uniqueId>` |
| Firewall rule context for 0.0.0.0/0 on private subnet | `asset.tags.fedramp_rule_justification` (operator) | Rule annotated with `note: REQUIRES-OPERATOR-INPUT: justify 0.0.0.0/0 on private subnet <id>`; `missing[]` += `rule-justification:<sg-uniqueId>:<ruleIndex>` |
| Cross-region peering purpose | `asset.tags.application` on either end | Edge label appends `REQUIRES-OPERATOR-INPUT: peering-purpose`; `missing[]` += `peering-purpose:<from>-><to>` |
| VPC CIDR (for legend) | `asset.tags.cidr` / native `cidrBlock` | VPC label renders `CIDR: REQUIRES-OPERATOR-INPUT`; `missing[]` += `vpc-cidr:<vpc-uniqueId>` |
| Region name for cloud container | `asset.location` | If `location` is empty: render in a `cloud "<Provider> / UNKNOWN-REGION REQUIRES-OPERATOR-INPUT"` container; `missing[]` += `region:<uniqueId>` |

The slice never substitutes a default CIDR or a placeholder region name.

## Test specifications (≥14 tests)
1. `it('groups assets by provider+region into cloud containers')` —
   fixture with AWS us-east-1 + AWS us-west-2 + GCP us-central1 yields
   three `cloud` containers.
2. `it('emits one node per VPC / VNet / network')` — 2 AWS VPCs +
   1 Azure VNet + 1 GCP network yields four `node` blocks.
3. `it('emits one frame per subnet inside its parent VPC with cidr + public/private label')` —
   asserts the exact label format `<subnet-id> · <cidr> · public|private`.
4. `it('classifies subnets as private when CIDR is in RFC1918')` —
   `10.0.1.0/24` with no IGW route → `private`.
5. `it('classifies subnets as public when CIDR is non-RFC1918 OR has IGW route')` —
   `10.0.0.0/24` with `mapPublicIpOnLaunch=true` AND IGW route → `public`.
6. `it('emits database nodes for RDS / Cloud SQL / Azure SQL placed in their subnet')`.
7. `it('emits peering/transit-gateway/vpn arrows from InventoryEdge[]')` —
   fixture with 3 `peering` edges + 1 `tgw-attachment` + 1 `vpn` yields
   five labelled arrows.
8. `it('emits cross-region doubled arrow when peering crosses regions')` —
   `from.region=us-east-1` and `to.region=us-west-2` → `==>` arrow with
   label `cross-region us-east-1→us-west-2`.
9. `it('emits firewall rule summary note with top-N rules per direction')` —
   fixture with 12 ingress + 8 egress rules and limit=5 → exactly 5
   ingress + 5 egress in the note.
10. `it('the rule summary cites every rule by SecurityGroup uniqueId in the manifest')` —
    every `manifest.firewall_rules[].source.assetUniqueId` resolves to a
    real `asset.uniqueId` in the fixture.
11. `it('emits REQUIRES-OPERATOR-INPUT for orphan subnet (no parent VPC)')`.
12. `it('emits REQUIRES-OPERATOR-INPUT for 0.0.0.0/0 rule on private subnet')`.
13. `it('respects --providers=aws to skip GCP/Azure assets')` —
    multi-cloud fixture with `providers=['aws']` yields only AWS clouds.
14. `it('is deterministic — same input → byte-identical puml + manifest')` —
    runs twice, sha256s the outputs, asserts equality. Requires a
    clock parameter from `runId`'s timestamp.
15. `it('throws MissingInventoryError when inventory.json absent')`.
16. `it('writes diagram-manifest naming every VPC/subnet/peering edge with source uniqueId')`.
17. `it('coverage-report fields vlan_network_id + ip_address are READ but not modified')` —
    snapshot the coverage report before+after; assert equality on
    those two rows (sanity check we don't accidentally regress
    coverage from this slice).

(Total: 17 tests in `network.test.ts`. The three shared modules ship
their tests with D.D1.)

## REO compliance specific to this slice
- **Every VPC / subnet / peering node** traces to a real
  `InventorySnapshot.assets[]` or `InventorySnapshot.edges[]` entry. No
  fabricated nodes or edges.
- **Firewall rule summary** is sourced from real `SecurityGroup` /
  `NSG` / `Firewall` resources (already enumerated by provider
  collectors into `asset.raw` and `asset.openPorts`). No "common
  pattern" rule fabricated.
- **No silent fallback for missing fields** — every miss surfaces as
  `REQUIRES-OPERATOR-INPUT` text in the diagram + a
  `manifest.requires_operator_input[]` entry.
- **Provenance fields populated**: `emitter`, `emitted_at`,
  `source_inventory_path`, `source_inventory_sha256`, `run_id`,
  `signing_key_id` (after sign step), `tool`, `version`,
  `firewall_rule_source_count` (number of rules cited from real SGs).
- **synthesized_fields[]** names every derived label (e.g.
  `'subnet-class:private (cidr+route-inference)'`,
  `'edge-label:cross-region us-east-1→us-west-2'`).
- **Signed by**: existing Ed25519 + RFC 3161 pipeline (allow-list
  already extended by D.D1).
- **CHANGELOG entry** names the slice + the module file + the test
  count delta + the verification result.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/diagrams/network.test.ts
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
  --network-diagram \
  --diagram-format=both \
  --out=out/dev
ls out/dev/network.{puml,svg,png}
jq '.requires_operator_input' out/dev/network-diagram-manifest.json
```

## Known risks / issues
- **Risk R-D2-1 (high)**: PlantUML subset renderer may not yet support
  some deployment-diagram shape (e.g. `frame` nested inside `node` more
  than two levels deep). **Mitigation**: extend the shared subset
  renderer; D.D1's grammar header comment tracks supported shapes.
  Failing tests in D.D2 → add shape → re-run all three diagram test
  suites (D.D1 / D.D2 / D.D3) to confirm no regression.
- **Risk R-D2-2 (high)**: large security-group rule counts (some AWS
  accounts have 500+ rules per SG) cause unreadable rule-summary notes.
  **Mitigation**: `firewallRuleSummaryLimit` default 5 limits each
  direction; full rule set still cited in the manifest for audit. The
  diagram is a summary, not the source of truth.
- **Risk R-D2-3 (med)**: AWS Network ACL rules are NOT in scope this
  slice (we only summarise security-groups). **Mitigation**: document
  in the manifest's `summary_scope` field that NACLs are excluded;
  follow-up slice can add them. The SC-7-family proof still holds
  because SGs are the per-instance enforcement layer.
- **Risk R-D2-4 (med)**: subnet public/private classification depends
  on route-table analysis the inventory snapshot may not have run on
  every subnet (INV-P2 best-effort). **Mitigation**: when route table
  not collected, render label as `subnet-id · <cidr> · class-unknown
  REQUIRES-OPERATOR-INPUT` and add to missing[]. Never default to
  `public` or `private`.
- **Risk R-D2-5 (med)**: cross-account peering edges only appear when
  both accounts are in the org-fan-out scan (INV-P3). Single-account
  runs miss the other end. **Mitigation**: when an edge has only one
  endpoint resolvable in the snapshot, render with
  `note: peer-vpc-uniqueId not in inventory; cross-account scan
  required` and a missing[] entry.
- **Risk R-D2-6 (low)**: GCP "default" network detection — a Network
  named `default` is auto-created on every project. Including it in
  the diagram clutters layout. **Mitigation**: render it; add a
  manifest synthesized field
  `'note:gcp-default-network-auto-created'` so a reviewer knows the
  CSP did NOT explicitly create it.
- **Risk R-D2-7 (low)**: Azure VNet peering can be one-way (initiator
  vs accepter). **Mitigation**: render as a single bidirectional arrow
  unless peering state shows `Initiated` (one-way) — then render
  `-->` with label `one-way: <initiator> → <accepter>`.

## Open questions (for implementation session to resolve)
- **Q1**: Should the rule-summary `note` show denied rules too, or
  only allow rules? Denied rules are useful for SC-7(5) "deny by
  default" proof. Propose: show both, sort allow-first; manifest
  cites both.
- **Q2**: For AWS VPC endpoints (interface + gateway), do we render
  as a dedicated `node` inside the VPC or as an edge between the VPC
  and the AWS-service `cloud`? Endpoint as an edge feels more accurate
  but inflates edge count. Propose: render as edge with label
  `endpoint:<service-name>:<type>`; manifest records both endpoints.
- **Q3**: Should cross-region edges go to a "global" container (a
  `cloud "Multi-region"` enclosing the two regional `cloud` boxes)?
  PlantUML layout would benefit. Propose: yes, when more than one
  region present; the global container is purely visual and carries
  no asset references in the manifest.
- **Q4**: For Azure, `Microsoft.Network/virtualHubs` (vWAN) is the
  Azure equivalent of TGW. Do we treat it as a TGW for diagram
  purposes? Propose: yes, render as `node "vWAN <id>"` with `==>`
  arrows to attached VNets.
- **Q5**: The firewall rule summary's "broadest first" sort needs a
  CIDR-size comparator. Propose: sort by `prefix_length ASC` (smaller
  prefix = larger range = broader) then by `port_range_size DESC`.
- **Q6**: Should we surface VPC-flow-log enablement on the diagram
  (e.g. green dot on VPCs with flow logs enabled)? This would tie to
  AU-12 (Audit Record Generation). Probably yes — propose: small
  `note bottom of vpcA: "flow-logs: ON"` or `"flow-logs: OFF
  REQUIRES-OPERATOR-INPUT"`. Verify INV-P3 collects this field.
- **Q7**: How to render an asset that lives in MULTIPLE subnets
  (multi-NIC VMs, ENI attachments)? Propose: render in the primary
  subnet (first ENI); add a `note: also-in <other-subnet-id>` for
  each additional. Manifest cites all subnet memberships.

## Implementation log (running journal — implementing session updates)
This section is filled in DURING implementation. Leave it empty with a
single placeholder line:
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by 17 for this slice's new
      tests in `network.test.ts`)
- [ ] check:reo green (G1 lint:no-stubs + G2 check:coverage-regression +
      G3 check:provenance)
- [ ] STATUS.md updated (D.D2 row + Overall section: last-shipped +
      next-priority)
- [ ] LOOP-D-SPEC.md §7 status table updated (D.D2 row)
- [ ] This file's frontmatter updated (status=done, commit=<hash>,
      completed_date=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (under
      "### Added — LOOP-D.D2: Network Diagram emitter")
- [ ] Commit with slice ID in message
      (`LOOP-D.D2: Network Diagram emitter`)
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
   `diagram-manifest.ts`) this slice REUSES (it does not redefine them).
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the
   mandatory 7-step commit pattern.
6. Inspect `cloud-evidence/core/inventory-workbook.ts` for the
   `CloudAsset`, `InventoryEdge`, `InventorySnapshot` interfaces.
7. Inspect `cloud-evidence/providers/aws/network.ts`,
   `providers/gcp/network.ts`, `providers/azure/network.ts` to
   confirm VPC / subnet / route / SG / NSG / firewall fields populate
   the snapshot fields this slice reads.
8. Inspect `cloud-evidence/core/diagrams/plantuml-render.ts` (shipped
   by D.D1) to confirm `frame`, `node`, `database`, `cloud`, doubled
   arrows are all in the grammar subset. If not, extend the subset
   FIRST then add a regression test in
   `tests/core/diagrams/plantuml-render.test.ts`.
9. Begin implementation; update the **Implementation log** section
   above as you go.

---

(end of D.D2 per-slice file)
