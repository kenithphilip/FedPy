# Design + roadmap: a complete, organization-grade cloud inventory

> Forward-looking design (not an external-repo analysis). Goal: evolve FedPy's
> inventory from "fills the FedRAMP Appendix M workbook" into a **complete cloud
> asset inventory for any organization** — every resource, every relevant data
> dimension, multi-account / multi-region / multi-cloud — with the FedRAMP
> workbook as just one *projection* of a richer model. Grounded in how mature
> tools (AWS Config, Resource Explorer, GCP Cloud Asset Inventory, Azure Resource
> Graph, CloudQuery, Steampipe, Cartography, ServiceNow CMDB) do it.

## Where we are today

`core/inventory-workbook.ts` + `providers/{aws,gcp}/inventory-assets.ts` enumerate
a **curated, hand-written set** of services (AWS: EC2/EBS/RDS/S3/Lambda/ELBv2/
DynamoDB/ECR/EKS/CloudFront; GCP: Cloud Asset Inventory over ~9 curated types),
normalize to a 25-field `CloudAsset`, and project to the FedRAMP 25-column
workbook with FedPy twists (tag enrichment, scan reconciliation, KSI cross-link).

**The completeness ceiling:** a hand-written per-service list never covers
"everything an org owns." AWS alone has 1,000+ resource types. Mature inventory
tools don't hand-enumerate — they ride a **generic discovery API** and enrich.

## The key architectural shift: generic discovery backbone + targeted enrichment

This is the single highest-leverage change. Instead of (only) per-service code,
use each cloud's resource-graph API for **breadth**, then per-service describe
calls for the **depth** fields the graph doesn't expose.

| Cloud | Generic discovery backbone (breadth = ALL resource types) | Notes / limits |
|---|---|---|
| **AWS** | **Config Advanced Query** (`SelectResourceConfig` / `SelectAggregateResourceConfig`) — SQL over every Config-recorded type, single endpoint, multi-account+region via an aggregator | needs Config recorder on (we already *check* for it in `inventory.ts`/CNA-EIS); can't unpack tags in SQL; only recorded types |
| AWS fallback | **Resource Explorer** (`resource-explorer-2:Search`) — no query language, multi-region/account | 1,000-result cap per query → page by type/region |
| AWS tags | **Resource Groups Tagging API** (`GetResources`) — tagged resources + their tags | tagged only (misses untagged) |
| **GCP** | **Cloud Asset Inventory** `searchAllResources` (broader than the `assets.list` + curated-types we use now — covers *all* asset types) | already have the client + `cloudasset.viewer` |
| **Azure** | **Azure Resource Graph** (KQL `Resources`) — every resource in one query | ties to the future Azure collector (AZ-1/2, report 03) |

**Design:** a provider-agnostic `discoverAll()` that returns a baseline
`CloudAsset` (id, type, name, account/project, region, tags, raw config) for
*every* resource, then **enrichment passes** that upgrade high-value types
(EC2→IP/MAC/OS, RDS→engine/EOL, S3→public/encryption) using the per-service code
we already have. Breadth from the backbone, depth from enrichment. Keep per-service
enrichers behind a registry so adding depth for a new type is one function.

## The complete data model — dimensions a robust org inventory needs

Our `CloudAsset` covers the basics; a complete inventory needs these dimensions.
"Status" = where FedPy is today.

| Dimension | Fields | Source | Status |
|---|---|---|---|
| **Identity** | provider, account/project/subscription, partition, canonical id (ARN/self-link), name, resource type | discovery backbone | ✅ partial (no account/sub, no type taxonomy) |
| **Location** | region, AZ/zone, global flag | discovery | ✅ |
| **Network** | private/public IPs, MAC, VPC/subnet, security groups/firewalls, DNS, ports/exposure, internet-facing | per-service + SG/firewall describe | 🟡 IP/MAC/VPC yes; SGs, ports, exposure no |
| **Compute spec** | instance type, vCPU, memory, arch, image/AMI id | per-service | 🟡 type/hardware yes; vCPU/mem/AMI no |
| **OS & software** | OS+version, installed packages, runtime, container image+digest, **SBOM linkage** | **SSM Inventory** / GCP OS Config; ECR/Artifact Registry; our SBOM report | 🟡 OS partial; no package/SBOM link |
| **Storage & data** | size, encryption-at-rest + **KMS key id**, public access, versioning, **data classification** | per-service; Macie/DLP; tags | 🟡 encryption flag only; no key/size/class |
| **Security posture** | public exposure, vuln/scan findings, patch compliance, misconfig findings, logging on, IMDSv2 | our findings + VDR + SSM patch | 🟡 scan + KSI cross-link done; no patch/posture flags |
| **Lifecycle** | created, last-modified, **last-used/last-activity**, state, **EOL date**, scheduled-deletion | per-service; CloudTrail/usage; EOL calendars | 🟡 none yet (EOL/created/state are quick wins) |
| **Ownership & org** | owner, team, cost center, **environment (prod/dev)**, application, business unit, **criticality** | tags (+ tag-governance) | ✅ tag-driven owner/function; no env/criticality/cost-center |
| **Cost** | monthly cost estimate, pricing model, billing tags | **Cost Explorer** / pricing API / CUR | ❌ |
| **Relationships / topology** | parent/child (instance→volume, LB→targets, cluster→nodes), dependencies, **graph edges** | per-service refs; Cartography-style | ❌ (high value — see below) |
| **Tag governance** | full tag set, **required-tag compliance**, tag-policy violations | tags vs a required-tag policy | 🟡 capture tags; no policy check |
| **Compliance** | in-boundary flag, KSI/control links, findings | our evidence (cross-link) | ✅ KSI cross-link + scan reconciliation |
| **Provenance** | collected_at, source API, collector version, freshness, confidence | collector | 🟡 partial (per-evidence, not per-asset) |
| **Change/drift** | added/removed/modified vs prior snapshot | snapshot diff (we have diff/anomaly infra) | ❌ |

## Enrichment sources worth wiring (the "all required data" part)

- **Software/package inventory** — AWS **SSM Inventory** (`ListInventoryEntries` / `GetInventory`) gives installed apps + OS + patches per managed instance; GCP **OS Config Inventory**. This fills OS, software vendor/version, patch level (workbook cols K/P/Q/R) *and* gives real software BOM. Link to our existing SBOM report for images.
- **Cost** — AWS **Cost Explorer** (`GetCostAndUsage` grouped by resource/tag) or the **Cost and Usage Report**; GCP **Billing BigQuery export**. Adds a cost column + FinOps value (a top reason orgs want inventory).
- **Data classification** — AWS **Macie** findings / GCP **DLP** results / a `data-classification` tag → classify storage assets (PII/PHI/PCI). Critical for any org's data map.
- **Relationships / topology** — derive edges from resource references (EC2→EBS/ENI/SG, ASG→instances, ELB→target groups→instances, EKS→nodegroups, RDS→subnet group→VPC). Emit a graph (nodes+edges) alongside the flat list — enables attack-path / blast-radius / dependency views (Cartography's whole value prop).
- **Lifecycle** — created/last-modified from each API; **last-used** from CloudTrail / Access Analyzer / usage metrics (idle-resource detection = cost + security win); **EOL** from a maintained map (RDS engine versions, Lambda runtimes, OS, K8s versions).
- **Tag governance** — check each asset against a configurable **required-tag policy** (e.g. must have Owner, Environment, CostCenter, DataClassification); emit violations. Drives the ownership columns *and* a governance report.
- **Network exposure** — resolve security groups / firewall rules + public IP/ELB scheme into an "exposure" assessment (open ports to 0.0.0.0/0). High security value, feeds column E.

## Service-coverage strategy

With the **generic backbone**, breadth stops being a hand-list: every recorded
type appears automatically. The hand-written enrichers then add depth for the
"top ~30 types that carry rich fields" (compute, storage, db, network, IAM, KMS,
containers, serverless, messaging, analytics). Untyped/long-tail resources still
appear (id/type/name/region/tags/raw-config) so nothing is missed — exactly the
CloudQuery model (default cols: Cloud, Type, Account, Name, Region, Tags; deep
columns where available).

Concretely, depth-enrichers to add beyond today's 10 AWS types: **EFS, FSx,
Redshift, ElastiCache, OpenSearch, DocumentDB, Neptune, SNS, SQS, Kinesis, MSK,
API Gateway, Step Functions, SageMaker, EMR, Glue, Secrets Manager, KMS, ACM,
Route53, security groups, ENIs, EIPs, NAT/IGW/TGW, WAF, Elastic Beanstalk,
ECS services/tasks, Auto Scaling groups, Backup vaults**. GCP/Azure breadth comes
free from CAI / Resource Graph; add GCP depth-enrichers for the top types.

## Completeness across scope (a current real gap)

- **Multi-region:** the inventory enumerator currently runs **only `regions[0]`**.
  A complete inventory must sweep **all configured regions** (and global services
  once). *Fix: loop `config.aws.regions`; mark global services to collect once.*
- **Multi-account / multi-project / multi-subscription:** reuse the existing AWS
  **Org fan-out** (`--aws-org-fanout`) for inventory; loop all GCP projects (we do);
  Azure management-group sweep later. Config **aggregator** gives org-wide breadth
  in one call — pairs perfectly with the backbone.
- **Dedup + stable identity:** a resource seen via backbone + enricher must merge
  to one row; key on canonical id (ARN/self-link).

## Outputs & integrations (beyond the workbook)

- `inventory.json` — the **full normalized model** (superset; the workbook/CSV are
  lossy projections). This becomes the source of truth other emitters read.
- `inventory-graph.json` — nodes + edges (topology) for visualization / attack-path.
- **OSCAL** — emit a `system-implementation.components` / inventory-items block so
  the inventory flows into the SSP pipeline (ties to SSP-1, report 10).
- **ServiceNow CMDB / CSDM** feed, **CSV/XLSX** (have), **SIEM/webhook** (have infra).
- **Change snapshots** — persist each run; diff to show added/removed/changed
  (reuse `core/diff-report.ts` + anomaly infra) → drift + "what changed this week".
- **Tracker surfacing** — download the workbook/JSON from the collector-runs view.

## Proposed architecture

```
core/inventory-model.ts        # the rich CloudAsset superset + relationship edges (pure types)
core/inventory-discover.ts     # provider-agnostic discovery orchestration + dedup/merge
providers/aws/discover.ts      # Config Advanced Query / Resource Explorer / Tagging backbone
providers/aws/enrich/*.ts      # per-type depth enrichers (registry: type -> enrich fn)
providers/gcp/discover.ts      # CAI searchAllResources backbone
providers/gcp/enrich/*.ts
providers/azure/*              # (later, with AZ-1/2)
core/inventory-enrich.ts       # cross-cutting: tags, scan-reconcile, KSI-link, cost, EOL, exposure, tag-governance
core/inventory-workbook.ts     # FedRAMP Appendix M projection (current) — one emitter among several
core/inventory-emit.ts         # JSON / graph / OSCAL / CMDB / CSV / XLSX emitters
```

Keep everything read-only + guardrail-wrapped; keep pure transforms unit-tested;
follow the offline-first + signed-manifest patterns.

## Prioritized backlog

Effort S/M/L. Builds on the shipped INV-1..5.

| ID | Item | Why | Effort | Priority |
|----|------|-----|--------|----------|
| INV-6 | **Multi-region sweep** (loop all regions; global-once) | correctness — today only region[0] | S | **P0** |
| INV-7 | **AWS generic discovery backbone** (Config Advanced Query + Resource Explorer fallback + Tagging API) → all resource types | the completeness unlock | L | **P0** |
| INV-8 | **GCP `searchAllResources` backbone** (all asset types, not curated list) | GCP completeness | M | P0 |
| INV-9 | **Rich `inventory.json`** superset model + emitter (workbook becomes a projection) | source-of-truth for all outputs | M | P0 |
| INV-10 | S3 public-exposure (col E) + KMS-key-per-resource + size/encryption depth | security + data dims | M | P1 |
| INV-11 | EOL derivation (RDS engines, Lambda/K8s runtimes, OS) (col Z) | lifecycle | S | P1 |
| INV-12 | SSM Inventory / GCP OS Config → OS + installed software + patch (cols K/P/Q/R) + SBOM link | software dim | M | P1 |
| INV-13 | Relationship graph (`inventory-graph.json`) — edges between assets | topology / blast-radius | M | P1 |
| INV-14 | Tag-governance: required-tag policy + violations report; env/criticality/cost-center cols | ownership + governance | S | P1 |
| INV-15 | Network exposure (SG/firewall → open-to-internet ports) | security | M | P1 |
| INV-16 | Cost enrichment (Cost Explorer / billing export) | FinOps | M | P2 |
| INV-17 | Data classification (Macie/DLP/tags) | data map | M | P2 |
| INV-18 | Change snapshots + inventory diff (reuse diff/anomaly) | drift / "what changed" | M | P2 |
| INV-19 | OSCAL inventory-items / components emitter | SSP pipeline tie-in | M | P2 |
| INV-20 | Tracker surfacing (download workbook/JSON) + `--inventory-only` fast mode | UX | S | P2 |
| INV-21 | ServiceNow CMDB / CSDM feed | enterprise integration | M | P2 |

### Suggested next sprint
1. **INV-6** (multi-region) + **INV-9** (rich `inventory.json`) — small, correctness + foundation.
2. **INV-7 / INV-8** (generic discovery backbone) — the completeness unlock; everything else enriches on top.
3. Then the P1 enrichers (S3/EOL/SSM-software/exposure/tag-governance) and the graph.

## Risks & guardrails

- **AWS Config dependency** for the best backbone (cost + must be enabled). Mitigate
  with the Resource Explorer / Tagging API fallback path and graceful degradation.
- **Rate limits / scale** at org+all-regions+all-types — reuse the adaptive limiter
  + token bucket; page hard; cache per run.
- **Cost** of Cost Explorer API calls ($0.01/req) — batch + cache.
- **PII in the inventory** itself (owner emails, IPs) — it's sensitive; keep it under
  the signed manifest + the read-only/least-privilege story; document handling.
- **Freshness** — stamp per-asset `collected_at` + source; Config data can lag.
- **Read-only invariant** extends to every new client (backbone + enrichers).
