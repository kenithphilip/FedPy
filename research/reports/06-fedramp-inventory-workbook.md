# Research report: FedRAMP Integrated Inventory Workbook (SSP Appendix A-13 / Appendix M)

> Part of the FedPy integration-research series. This is a *deliverable format*,
> not a code repo — the canonical spreadsheet every FedRAMP package must attach.
> The user's explicit ask: "I want to do the same with AWS, GCP as well" — i.e.
> auto-generate this workbook for both clouds from FedPy's collected data.

- **Source (current):** `https://www.fedramp.gov/resources/templates/SSP-Appendix-M-Integrated-Inventory-Workbook-Template.xlsx` (the legacy `SSP-A13-…` Rev4 URL the user gave now 404s; FedRAMP renamed A-13 → **Appendix M**).
- **Local download:** `research/downloads/inventory-AppendixM.xlsx` (git-ignored, 254 KB, real OOXML; the `rev4` URL returns a 99-byte error page).
- **Format:** `.xlsx`, three sheets — `INSTRUCTIONS`, **`Inventory`** (the one that matters), `Record of Changes`.
- **License/usage:** U.S. Government work (public domain); we replicate the *format*, no licensing concern.
- **Directly relevant analog tools found while sourcing this:**
  - **aws-samples/fedramp-integrated-inventory-workbook** (Apache-2.0, Python Lambda) — generates this very workbook from AWS Config + ADS. The closest sanctioned reference design.
  - **google/asset-inventory-worksheet** / PyPI `asset-worksheet` (Apache-2.0) — the **GCP** equivalent (Cloud Asset Inventory → worksheet). Directly serves the "…and GCP" half.

## 1. What it does

The Integrated Inventory Workbook is the machine-readable asset inventory a CSP
submits as an SSP attachment. Assessors and the PMO use it to (a) confirm the
authorization boundary is fully enumerated, (b) reconcile the inventory against
vulnerability-scan results (every scannable asset must appear), and (c) track
ownership, OS/patch baselines, and end-of-life. It is a hard gate: an incomplete
or scan-mismatched inventory is a common assessment finding.

FedPy already *enumerates* cloud resources (the `KSI-PIY-GIV` inventory
collectors), but emits them as pass/fail evidence findings — **not** as this
spreadsheet. Producing a submission-ready workbook for AWS and GCP is the gap.

## 2. Architecture & key components — the exact column schema

The `Inventory` sheet header is **row 2**; rows 3–4 carry per-column GUIDANCE and
"Valid Values" (deleted before submission). Columns **B–Z (25 data columns)**,
grouped by the row-1 banner:

| Col | Header | Group | Valid values / guidance (abridged) |
|-----|--------|-------|------------------------------------|
| B | **Unique Asset Identifier** | All Inventories | Must be unique; typically IP/URL/DNS; for containers repo/image/version |
| C | **IPv4 or IPv6 Address** | All | One row per IP if multiple; container = registry checksum |
| D | **Virtual** | All | Yes / No |
| E | **Public** | All | Yes / No — is it outside the boundary / an entry point |
| F | **DNS Name or URL** | All | Valid DNS/URL or blank |
| G | NetBIOS Name | OS/Infra | Valid NetBIOS or blank |
| H | **MAC Address** | OS/Infra | Valid MAC or blank |
| I | Authenticated Scan | OS/Infra | Yes / No |
| J | **Baseline Configuration Name** | OS/Infra | STIG / CIS L2 benchmark name(s) applied |
| K | **OS Name and Version** | OS/Infra | OS + version |
| L | **Location** | OS/Infra | Data center / region identifiers |
| M | **Asset Type** | OS/Infra | Router, Storage Array, DNS Server, … (no vendor/product names) |
| N | **Hardware Make/Model** | OS/Infra | Hardware product + model |
| O | In Latest Scan | OS/Infra | Yes / No |
| P | **Software/Database Vendor** | SW/DB | "Open Source" if none |
| Q | **Software/Database Name & Version** | SW/DB | product + version |
| R | Patch Level | SW/DB | If applicable |
| S | Diagram Label | Any | Label on the SSP boundary diagram |
| T | Comments | Any | Free text |
| U | **Serial #/Asset Tag #** | Any | Serial or internal asset tag |
| V | **VLAN/Network ID** | Any | VLAN or Network ID |
| W | System Administrator/Owner | Any | Name |
| X | Application Administrator/Owner | Any | Name |
| Y | **Function** | Any | Function the component provides |
| Z | End-of-Life | Any | m/d/yyyy EOL date |

(Bold = realistically auto-fillable from read-only cloud APIs; see §4.)

> **Version note:** the older A-13 (the format `manywho/awsinventory` targets, see
> report 05) had 23 columns. Appendix M **adds `Diagram Label` (S) and
> `End-of-Life` (Z)**, makes column J explicitly the hardening-benchmark (STIG/CIS)
> name, and reorders slightly. FedPy should target **Appendix M** (current) and
> keep the column list in one constant so a future template revision is a one-line
> change.

## 3. What's genuinely interesting for FedPy

- **A fixed, known output contract.** 25 columns with official guidance — this is
  a spec we can hard-code and fill, not a moving target. Reports 05 (awsinventory)
  and the two analog repos already prove the resource→column mapping is tractable.
- **It dovetails with data we already collect.** `providers/aws/inventory.ts` and
  `providers/gcp/inventory.ts` (KSI-PIY-GIV) already call the discovery APIs; the
  network/data/crypto collectors already learn public-exposure, IPs, engines, and
  encryption. The workbook is largely a *re-projection* of evidence we hold.
- **Scan reconciliation is a feature we're positioned for.** Column O ("In Latest
  Scan") + our existing VDR collector (`providers/aws/vdr-scan.ts`, Inspector/ECR)
  means FedPy could cross-check the inventory against actual scan coverage — the
  exact reconciliation assessors do by hand.
- **Two sanctioned reference designs exist** for the hard part (resource→row
  mapping), both Apache-2.0: AWS-samples (AWS Config-driven) and Google's
  asset-worksheet (Cloud Asset Inventory-driven). We can mirror their field logic
  in TS without license friction.

## 4. Gaps in OUR stack this could fill — auto-fill analysis

FedPy has **no inventory-workbook output** at all. Mapping each column to what our
read-only collectors can supply today (AWS / GCP):

| Auto-fillable now (high confidence) | Source in FedPy / cloud API |
|---|---|
| B Unique ID, U Serial/Tag | resource ARN / GCP self-link / resource id |
| C IP, H MAC | EC2 `DescribeNetworkInterfaces` (private/public IP, MAC); GCP instance NICs (MAC not exposed → blank) |
| D Virtual | always "Yes" for cloud-managed assets |
| E Public | we already detect public exposure (network.ts: internet-facing ELB, public IP; data.ts: public buckets) |
| F DNS | Route 53 / Cloud DNS, ELB/CloudFront/API-GW DNS names, GCLB |
| K OS Name/Version | EC2 SSM Inventory / AMI platform; GCP instance `guestOsFeatures`/OS |
| L Location | region / AZ / zone |
| M Asset Type | derive from resource type (EC2→"Compute Instance", RDS→"Database", …) |
| N Hardware Make/Model | "AWS EC2 \<instanceType\>" / "GCP \<machineType\>" |
| P/Q Software/DB Vendor+Version | RDS engine+version, OpenSearch, ElastiCache, Lambda runtime, Cloud SQL |
| V VLAN/Network ID | VPC/subnet id; GCP VPC/subnet |
| Y Function | from tags/labels or asset-type default |
| Z End-of-Life | derive from RDS engine / Lambda runtime / OS deprecation calendars |

| Needs enrichment or manual input | Plan |
|---|---|
| G NetBIOS | leave blank (rarely available in cloud) |
| I Authenticated Scan, O In Latest Scan | default by asset type; reconcile O against our VDR/Inspector data |
| J Baseline Config (STIG/CIS) | from SSM patch baseline / hardened-image tags, else config-supplied default |
| R Patch Level | SSM patch compliance / GCP OS patch |
| S Diagram Label, T Comments | config-supplied or blank |
| W/X Owners | from an `Owner`/`AppOwner` resource tag (config-mappable) |

Net: **~16 of 25 columns auto-fill**, the rest fall back to tags/config/blank with
clear provenance — a genuinely useful, submission-grade draft.

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Effort | Priority |
|---|-------------|--------------|----------|--------|----------|
| 1 | Define the Appendix M column contract as a typed constant + row model | `cloud-evidence/core/inventory-workbook.ts` (new) | Encode the 25 columns + groups + valid-value enums once | S | P0 |
| 2 | AWS resource→row mapper | reuse `providers/aws/inventory.ts` + add ENI (IP/MAC), SSM Inventory (OS/patch), RDS/Lambda/OpenSearch (SW/DB) | Mirror aws-samples + report 05 field logic in TS | M | P0 |
| 3 | GCP resource→row mapper | reuse `providers/gcp/inventory.ts` + Cloud Asset Inventory | Mirror google/asset-worksheet field logic | M | P0 |
| 4 | Emit real `.xlsx` (not just CSV) | `core/inventory-workbook.ts` via `exceljs` (MIT) | Write the `Inventory` sheet with header; optionally CSV too via existing `core/csv-export.ts` | S | P1 |
| 5 | Owner/Function/Baseline from tags | config: tag→column map | `Owner` tag→W, `env`/`Function` tag→Y, image tag→J | S | P1 |
| 6 | Scan reconciliation (column O) | cross-ref `providers/aws/vdr-scan.ts` / Inspector coverage | Flag inventory assets missing from scans | M | P1 |
| 7 | `--inventory-workbook` CLI flag + orchestrator wiring | `core/orchestrator.ts` | Emit `out/inventory-workbook.xlsx` after collection, cover under the signed manifest | S | P1 |
| 8 | Tracker surfacing / download | `tracker/` | Offer the generated workbook as a download alongside collector runs | M | P2 |

## 6. Risks, caveats, licensing

- **Format is public-domain**; the analog generators are Apache-2.0 (compatible) —
  but they're Python; we port the *field logic*, not the code.
- **Completeness is the assessor's bar.** A partial inventory is worse than none if
  it implies the boundary is small. Mark un-fillable columns explicitly and document
  that the output is a *draft to be completed*, never an authoritative submission.
- **One-row-per-IP rule** (column C guidance) means multi-NIC / multi-IP assets
  expand into multiple rows — the mapper must fan out, not collapse.
- **Containers** have their own identity rule (registry checksum) — handle ECR/GCR/
  Artifact Registry images distinctly from VMs.
- **Template drift:** keep the column list in one constant (opportunity #1) so the
  next FedRAMP revision is a trivial change.

## 7. Verdict

**High value, high feasibility — arguably the single best ROI in this whole research
batch.** It's a fixed format, ~16/25 columns auto-fill from data FedPy already
collects, two Apache-2.0 reference designs de-risk the field mapping for *both*
clouds, and it directly answers the user's "do the same for AWS and GCP" ask. Build
`core/inventory-workbook.ts` as a re-projection of existing inventory evidence,
emit `.xlsx` via exceljs behind an `--inventory-workbook` flag, and reconcile
column O against our VDR scan data for a differentiator assessors will notice.
