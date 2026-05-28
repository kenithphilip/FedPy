# Research report: manywho/awsinventory

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/manywho/awsinventory
- **Local clone:** `research/clones/awsinventory` (git-ignored)
- **Language / stack:** Go 1.12, AWS SDK for Go v1 (`github.com/aws/aws-sdk-go`), `spf13/pflag`, `sirupsen/logrus`. ~2,480 LOC non-test (~1,200 LOC of actual collectors), plus a near-1:1 test file per service.
- **License:** **GPLv3** (`LICENSE.md`). ← integration-relevance: **copyleft, incompatible with our Apache-2.0**. We can read it as a spec and reuse the *column mapping + service coverage*, but we must NOT copy/port its Go source into FedPy. (See §6.)
- **Activity / maturity:** Last commit `e2d6844` 2021-03-19 (a Dependabot testify bump). Effectively dormant for ~4 years; pre-1.0; no tags in the shallow clone but the README points at GitHub releases. Mature *design*, stale *dependencies* (AWS SDK Go v1, now in maintenance mode). Small, clean, well-tested.
- **One-line:** A Go CLI that enumerates AWS resources across 17 services and emits a CSV that matches the **FedRAMP Integrated Inventory Workbook (SSP Appendix A-13)** column layout.

## 1. What it does

`awsinventory` is a single-purpose command-line tool: point it at one or more AWS regions, give it AWS credentials via the standard default-credential chain (`~/.aws/credentials`, `~/.aws/config`, SSO, env vars), and it walks 17 AWS services, describing every resource it finds and writing one CSV row per asset. The CSV header is hand-built to mirror the columns of the official [FedRAMP Integrated Inventory Workbook template](https://www.fedramp.gov/assets/resources/templates/SSP-A13-FedRAMP-Integrated-Inventory-Workbook-Template.xlsx) (`README.md` line 12). The intended user is a CSP engineer assembling the asset-inventory artifact that 3PAOs and the JAB/agency expect as part of an SSP package.

It is read-only by construction — every AWS call is a `List*` / `Describe*` / `Get*` operation; nothing mutates. There is no auth/RBAC layer of its own; it inherits whatever the caller's AWS identity can see.

The output is **CSV only** — it does *not* write a real `.xlsx`. The README is explicit that it "aims to output a CSV in accordance to" the workbook; producing the actual multi-tab Excel workbook is left to the operator (paste the CSV into the template). This is the single biggest gap between what it does and the deliverable assessors actually want (a populated `.xlsx`), and it's exactly the gap FedPy would need to close.

CLI surface (`cmd/awsinventory/awsinventory.go`): `--regions/-r` (repeatable), `--services/-s` (subset of the 17, defaults to all), `--output-file/-o` (default `inventory.csv`), `--print-regions`, `--log-level/-l`, `--version`.

## 2. Architecture & key components

Three internal packages plus one helper:

- **`internal/inventory/`** — the *output contract*. `row.go` defines the 23-field `Row` struct (the workbook columns) and `Row.StringSlice()` which serializes a row in fixed column order; booleans render as `"Yes"/"No"` via `getBoolString`. `csv.go` holds `csvHeaders` (the 23 human-readable column titles), `NewCSV`/`WriteRow`/`Flush`. This package is the clean, language-agnostic spec we care about.
- **`internal/awsdata/`** — the *collectors*. `data.go` is the orchestrator: `AWSData` holds an injected `Clients` interface, a buffered `chan inventory.Row` (capacity 100), and a `sync.WaitGroup`. `Load(regions, services, processRow)` validates inputs, spawns one goroutine per (service × region), and a single worker goroutine drains the channel and calls the caller-supplied `processRow` callback (the CLI's callback writes each row to CSV). One `*.go` file per service (`ec2.go`, `s3.go`, `rds.go`, …) each exposing `load<Service>(region)` → describe/paginate → emit `inventory.Row`s. `clients.go` defines the `Clients` interface and `DefaultClients` factory (one constructor per service, region-scoped); injection is what makes every collector unit-testable with mocks (`*_test.go`).
- **`pkg/route53cache/`** — a small DNS-enrichment cache: at startup (if EC2 is in scope) it pulls all Route53 hosted-zone record sets once, then `FindRecordsForInstance` matches an instance's private/public IP or DNS name against CNAME/A records to populate the **DNS Name or URL** column for EC2. Nice touch — it turns raw IPs into the friendly DNS names assessors expect.
- **`process_row.go`** — just the `type ProcessRow func(inventory.Row) error` callback type, so output format is fully decoupled from collection.

**Concurrency model:** fan-out/fan-in. `data.go` `Load()` adds to the WaitGroup per service×region goroutine; richer collectors (EC2, ECS, S3, ElastiCache, KMS, ECR, DynamoDB) add *more* goroutines per resource (`d.wg.Add(1); go d.process…`). All feed the shared `rows` channel; a single `startWorker` consumer serializes writes. When the WaitGroup drains, `close(d.rows)` signals done. Errors are logged (logrus) and the offending collector returns — a failed service never aborts the run (resilient, partial-result friendly).

**Regions/accounts:** Region list comes from the SDK's endpoint resolver (`endpoints.DefaultResolver().Partitions()`), validated against `--regions`. CloudFront and IAM are treated as **global** (run once, region `"global"`); everything else runs per-region. **Account ID** is *not* taken from STS — it's scraped opportunistically from the first Security Group's `OwnerId` (`ec2.go`, `ebs.go`, `elb.go`), used only to hand-build ARNs for services whose API doesn't return one. **Single account only** — there is no multi-account/Organizations fan-out; you'd run the binary once per account/profile.

## 3. What's genuinely interesting for FedPy

This is the **closest existing analog to a feature FedPy wants**: it is a working, field-tested specification of "AWS resource → FedRAMP inventory row." The two reusable assets are (a) the **exact column contract** and (b) the **per-service field mapping**.

### 3a. The exact output columns (the workbook contract)

From `internal/inventory/csv.go` (header) and `row.go` (struct), in fixed order:

| # | CSV header (`csv.go`) | `Row` field (`row.go`) | Type |
|---|------------------------|------------------------|------|
| 1 | Unique Asset Identifier | `UniqueAssetIdentifier` | string |
| 2 | IPv4 or IPv6 Address | `IPv4orIPv6Address` | string (newline-joined) |
| 3 | Virtual | `Virtual` | Yes/No |
| 4 | Public | `Public` | Yes/No |
| 5 | DNS Name or URL | `DNSNameOrURL` | string (newline-joined) |
| 6 | NetBIOS Name | `NetBIOSName` | string (always empty — never populated) |
| 7 | MAC Address | `MACAddress` | string (newline-joined) |
| 8 | Authenticated Scan | `AuthenticatedScan` | Yes/No (always "No") |
| 9 | Baseline Configuration Name | `BaselineConfigurationName` | string |
| 10 | OS Name and Version | `OSNameAndVersion` | string |
| 11 | Location | `Location` | string (= region) |
| 12 | Asset Type | `AssetType` | string |
| 13 | Hardware Make/Model | `HardwareMakeModel` | string |
| 14 | In Latest Scan | `InLatestScan` | Yes/No (always "No") |
| 15 | Software/Database Vendor | `SoftwareDatabaseVendor` | string |
| 16 | Software/Database Name & Version | `SoftwareDatabaseNameAndVersion` | string |
| 17 | Patch Level | `PatchLevel` | string (always empty) |
| 18 | Function | `Function` | string |
| 19 | Comments | `Comments` | string |
| 20 | Serial #/Asset Tag # | `SerialAssetTagNumber` | string (= **ARN**) |
| 21 | VLAN/Network ID | `VLANNetworkID` | string (= **VPC ID**) |
| 22 | System Administrator/Owner | `SystemAdministratorOwner` | string (always empty) |
| 23 | ApplicationAdministrator/Owner | `ApplicationAdministratorOwner` | string (always empty) |

Note the **6 columns it never fills** (NetBIOS, Authenticated Scan, In Latest Scan, Patch Level, Sys-Admin, App-Admin) — these require scan-tool integration (Nessus/Tenable) or org-chart data that an API walk can't supply. That's a precise, honest map of "what cloud APIs *can* answer" vs. "what humans/scanners must fill in" — directly useful for FedPy's UX (auto-fill the API columns, prompt/leave-blank the rest).

### 3b. Resource-type → row mapping per service (the real signal)

17 services, each with a fixed `AssetType` string and a discrete set of AWS calls. Citations are file + the key API call(s) and which columns get populated.

| Service (`-s` key) | AssetType | AWS API calls (file) | Columns populated (besides Asset Type / Location / Serial=ARN) |
|---|---|---|---|
| `ec2` | `EC2 Instance` | `DescribeInstances` (paginated, running/stopping/stopped), `DescribeImages` (AMI→OS), `DescribeSecurityGroups` (acct id) + Route53 cache (`ec2.go`) | IP (public+all private/primary), Virtual=Yes, Public (if public IP/DNS), DNS (Route53+public/private DNS), MAC (per ENI), Baseline=AMI id, OS=AMI name, Hardware=InstanceType, Function=Name tag, VLAN=VpcId |
| `ebs` | `EBS Volume` | `DescribeVolumes` (`ebs.go`) | Virtual=Yes, Hardware=`type (NN GB)`, Function=Name tag |
| `s3` | `S3 Bucket` | `ListBuckets` + `GetBucketLocation` (region filter) (`s3.go`) | Virtual=Yes |
| `rds` | `RDS Instance` | `DescribeDBInstances` (`rds.go`) | Virtual=Yes, Public=PubliclyAccessible, DNS=Endpoint.Address, Hardware=DBInstanceClass, SW vendor=Engine, SW name+ver=`Engine EngineVersion`, VLAN=DBSubnetGroup.VpcId |
| `dynamodb` | `DynamoDB Table` | `ListTables` + `DescribeTable` (`dynamodb.go`) | Virtual=Yes, Public=No, SW vendor=Amazon, SW name=DynamoDB, Comments=table size (human bytes) |
| `lambda` | `Lambda Function` | `ListFunctions` (`lambda.go`) | Virtual=Yes, Baseline=Version, OS="Amazon Linux", SW name+ver=Runtime, Function=Description, Comments=`timeout s, mem MB`, VLAN=VpcConfig.VpcId |
| `elb` | `ELB` (classic) | `DescribeLoadBalancers` (elb) + SG for acct (`elb.go`) | Virtual=Yes, Public=(scheme internet-facing), DNS=DNSName, Function=CanonicalHostedZoneName, VLAN=VPCId; ARN hand-built |
| `elbv2` | `ALB`/`NLB`/`GLB` (by `Type`) | `DescribeLoadBalancers` (elbv2) (`elbv2.go`) | IP (per-AZ v4/v6/private), Virtual=Yes, Public=(scheme), DNS=DNSName, VLAN=VpcId |
| `ecs` | `ECS Container` | `ListClusters`→`DescribeClusters`→`ListTasks`→`DescribeTasks`, `DescribeNetworkInterfaces` (`ecs.go`) | UID=`name-runtimeId`, IP (ENI v4/v6), MAC, Baseline=Image, Hardware=LaunchType(+Fargate ver), Function=`cluster group`, VLAN=ENI VpcId |
| `ecr` | `ECR Image` | `DescribeRepositories`→`DescribeImages` (`ecr.go`) | UID=`repo-digest`, Public=No, DNS=RepositoryUri, Function=image tags, Comments=image size, Serial=ImageDigest |
| `elasticache` | `ElastiCache Node` | `DescribeCacheClusters` (ShowCacheNodeInfo) + `DescribeCacheSubnetGroups` (`elasticache.go`) | per-node UID=`cluster-node`, DNS=node endpoint, Baseline=param group, Hardware=CacheNodeType, SW vendor=Engine, SW name+ver, VLAN=subnet-group VpcId |
| `es` | `Elasticsearch Domain` | `ListDomainNames`→`DescribeElasticsearchDomains` (batched ≤5) (`es.go`) | DNS=Endpoints["vpc"], Hardware=InstanceType, SW vendor=Elastic, SW name+ver=`Elasticsearch X`, VLAN=VPCOptions.VPCId |
| `cloudfront` | `CloudFront Distribution` (global) | `ListDistributions` (`cloudfront.go`) | Virtual=Yes, Public=Yes, DNS=domain+aliases, Baseline=origin domains, Function=Comment |
| `codecommit` | `CodeCommit Repository` | `ListRepositories`→`BatchGetRepositories` (`codecommit.go`) | UID=`name-id`, DNS=CloneUrlHttp, Function=Description |
| `iam` | `IAM User` (global) | `ListUsers` (`iam.go`) | Virtual=Yes; UID=UserName, Serial=Arn |
| `kms` | `KMS Key` | `ListKeys`→`DescribeKey` (`kms.go`) | Baseline=Origin, Function=Description, Comments=`manager, spec` + created/valid-to dates |
| `sqs` | `SQS Queue` | `ListQueues`→`GetQueueAttributes` (`sqs.go`) | UID=queue name (from URL), DNS=queue URL, Comments=approx msg counts |

Cross-cutting conventions worth stealing wholesale: **Serial #/Asset Tag # = the resource ARN** (universal stable identifier; hand-built from partition+region+account when the API omits it); **VLAN/Network ID = VPC ID**; **Location = region**; **Virtual = Yes** for essentially everything (these are all cloud/virtual assets); **Public** derived from scheme / public IP / `PubliclyAccessible`; multi-value fields (IPs, MACs, DNS) newline-joined inside one cell.

### 3c. Patterns

- **Output decoupled from collection** via the `ProcessRow` callback — FedPy can mirror this so the same collected rows feed CSV *and* a real `.xlsx`.
- **Mockable client interface** (`Clients`) → 100% unit-tested collectors. FedPy's existing `core/auth/aws.ts` factory functions already give us the same injection seam.
- **Route53 DNS enrichment** to fill the "DNS Name or URL" column for compute assets.
- **Graceful per-service degradation** — log + skip on error, never abort.

## 4. Gaps in OUR stack this could fill

**The headline gap:** FedPy does **not** produce the FedRAMP Integrated Inventory Workbook at all. Our existing `providers/aws/inventory.ts` and `providers/gcp/inventory.ts` are *misnamed* for this purpose — they are KSI-PIY-GIV *compliance checks* ("is AWS Config Aggregator / GCP Cloud Asset Inventory present?"), emitting pass/fail `finding` objects. They **do not enumerate individual resources** and contain none of the per-asset data (IP/DNS/MAC/OS/ARN) the workbook needs. So the "reuse existing inventory data" framing in the task is only partly true: the *file names* overlap, but the *resource-level enumeration does not yet exist in FedPy.*

What this repo shows us we're missing, mapped to concrete surfaces:

- **`cloud-evidence/core/` — no inventory-workbook emitter.** We have `core/csv-export.ts` (one row per *finding*) and `core/html-report.ts`, but nothing that emits the 23-column asset workbook. New module needed: `core/inventory-workbook.ts`.
- **`cloud-evidence/providers/aws/` — no per-resource enumerator.** Need a new collector (`providers/aws/asset-inventory.ts`) that does `Describe*` walks like awsinventory's 17 services and produces typed asset rows, not findings.
- **`cloud-evidence/providers/gcp/` — same gap, and awsinventory gives us no GCP help** (it's AWS-only). GCP enumeration would lean on Cloud Asset Inventory (`cloudasset.assets.list`, already wired in `gcp/inventory.ts`) which returns a typed asset stream we'd map to the same 23 columns.
- **Real `.xlsx` output.** awsinventory stops at CSV; assessors want the populated multi-sheet workbook. FedPy can go further using the **`anthropic-skills:xlsx` skill / a Node xlsx library** to write the actual template. This is a *net improvement* over the analog.
- **Client coverage check.** FedPy's `core/auth/aws.ts` already exposes clients for **EC2, S3, RDS, DynamoDB, Lambda, ELBv2, CloudFront, ECR, KMS, IAM, EKS** — i.e. 11 of awsinventory's 17 services are immediately collectible. **Missing clients** (would need adding): **classic ELB, ECS, ElastiCache, Elasticsearch/OpenSearch (`es`), CodeCommit, SQS, Route53** (Route53 only needed for the DNS-enrichment nicety).

### What data we already have vs. need to additionally collect (for the AWS workbook)

| Workbook column | Have today? | Source |
|---|---|---|
| Unique Asset Identifier, Asset Type, Location, Serial(ARN), VLAN(VPC), Virtual, Public, DNS, SW vendor/name+ver, Hardware, Function | **Yes — derivable now** | Existing SDK clients (EC2/S3/RDS/etc.) via the same `Describe*` calls awsinventory uses |
| IP address, MAC | **Partly** | EC2/ELBv2/ECS describe calls return them; need the new enumerator to capture (we don't today) |
| OS Name & Version | **Partly** | EC2 via `DescribeImages` (AMI name); Lambda hard-codes "Amazon Linux" |
| Baseline Configuration Name | **Yes** | AMI id / param group / image / version per service |
| NetBIOS, Authenticated Scan, In Latest Scan, Patch Level, Sys-Admin Owner, App-Admin Owner | **No — not API-derivable** | Need scanner integration (Inspector/Nessus) + human/CMDB input; leave blank or prompt, exactly as awsinventory does |

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Adopt the **23-column workbook contract** verbatim as a TS type + header list | `cloud-evidence/core/inventory-workbook.ts` (new): `InventoryRow` interface + `WORKBOOK_COLUMNS` + Yes/No bool render + newline-joined multi-values | **Idea/spec** (re-author in TS; do NOT copy GPL Go). The column list/order is a FedRAMP fact, not their IP. | S | P0 |
| 2 | Build an **AWS per-resource enumerator** mirroring the 17-service field mapping in §3b | `providers/aws/asset-inventory.ts` (new) using existing `core/auth/aws.ts` clients | **Port the mapping spec** (which API → which column), re-implemented with AWS SDK **v3** and FedPy's read-only guardrail | M | P0 |
| 3 | Add the **6 missing AWS SDK clients** (ELB classic, ECS, ElastiCache, OpenSearch, CodeCommit, SQS) + optional Route53 | `core/auth/aws.ts` | Add `wrapAwsClient`-wrapped factories following the existing pattern | S | P1 |
| 4 | **GCP enumerator** feeding the same 23 columns | `providers/gcp/asset-inventory.ts` (new) | **Idea only** (awsinventory is AWS-only). Use `cloudasset.assets.list` (already wired in `gcp/inventory.ts`); map asset types (compute.instance→EC2-equiv, storage.bucket→S3-equiv, sqladmin→RDS-equiv, etc.) to AssetType + columns | M | P1 |
| 5 | Emit a **real populated `.xlsx`** workbook (not just CSV) — go beyond the analog | `core/inventory-workbook.ts` + `anthropic-skills:xlsx` skill / Node `exceljs` | Write the official A-13 template sheet with our rows; also offer CSV fallback (reuse `core/csv-export.ts` pattern) | M | P0 |
| 6 | **Route53 DNS enrichment** for compute assets' DNS column | enumerator helper, mirrors `pkg/route53cache` | **Idea** (re-author): pull hosted-zone record sets once, match instance IP/DNS | S | P2 |
| 7 | **ARN-as-Serial / VPC-as-VLAN / region-as-Location** conventions | enumerator field-fill logic | **Idea** (1-line conventions) | XS | P0 |
| 8 | **Honest "API can't fill these" handling** for the 6 blank columns | workbook emitter | **Idea**: leave blank + optionally cross-reference Inspector data (we already have `inspector2` client) for Patch/Scan columns — a FedPy enhancement | S | P2 |

## 6. Risks, caveats, licensing

- **License is the hard blocker for code reuse.** awsinventory is **GPLv3**; FedPy is **Apache-2.0**. GPLv3 is copyleft and **incompatible with redistributing FedPy under Apache-2.0 if we incorporate its code**. We must treat this repo as a **specification only**: the FedRAMP column list, the per-service "which API → which field" mapping, and the architectural patterns are facts/ideas we can freely re-author in TypeScript; the actual Go source must not be copied or mechanically translated. The column names themselves come from the public FedRAMP template, so they carry no GPL taint regardless.
- **Language mismatch.** Go + AWS SDK Go **v1**. FedPy is TypeScript on AWS SDK **v3**. Even if licensing allowed it, nothing is line-portable — every collector is a re-implementation. This is fine: the value is the mapping table in §3b, which is SDK-version-agnostic.
- **Staleness.** Last meaningful work ~2021; AWS SDK Go v1 is in maintenance mode; "Elasticsearch Service" is now "OpenSearch Service"; newer high-value asset types are absent (**EKS clusters, EFS, Redshift, EC2 *AMIs/snapshots as assets*, API Gateway, SNS, Step Functions, Secrets/SSM params**). FedPy should treat the 17 as a *floor*, not a ceiling — and we already collect several of these for other KSIs.
- **Account ID via Security Group OwnerId** is a hack; FedPy should instead use STS `GetCallerIdentity` (already in `core/auth/aws.ts` `whoAmI`) to build ARNs reliably.
- **Single-account only.** No Organizations fan-out. FedPy already has multi-account fan-out (task C.2); the inventory enumerator should plug into that so the workbook spans all in-scope accounts.
- **CSV-only output** means it doesn't actually deliver the assessor artifact (`.xlsx`); a FedPy implementation that writes the real workbook is strictly better.
- **6 columns are structurally unfillable from cloud APIs** — set correct expectations: the workbook will always need scanner + human input for NetBIOS, Authenticated/Latest Scan, Patch Level, and the two Owner columns.

## 7. Verdict

**High-value, low-cost — but as a blueprint, not a dependency.** This is the single best reference we have for the inventory-workbook feature: it answers, service-by-service, the hard question of *which AWS API call fills which FedRAMP column*, and it does so in production-tested, fully-tested code. The GPLv3 license and Go/SDK-v1 stack mean we copy **zero lines** — but the §3b mapping table and the 23-column contract in §3a de-risk perhaps **60–70% of the AWS side** of a FedPy inventory-workbook feature (the design and field-derivation logic), leaving us the mechanical work of re-authoring it on AWS SDK v3 plus the genuinely new work of GCP enumeration and real-`.xlsx` emission. **Highest-value single takeaway:** the resource-type → workbook-column mapping in §3b — lift it as a spec into `cloud-evidence/core/inventory-workbook.ts` + `providers/aws/asset-inventory.ts`, extend it to GCP via Cloud Asset Inventory, and emit the populated A-13 `.xlsx`.
