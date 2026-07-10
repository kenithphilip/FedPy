# fedramp_inventory_export — Cloud Inventory & FedRAMP Compliance Workbook

A **read-only** tool that turns a FedPy `cloud-evidence` run into a single,
stakeholder-ready **Excel workbook** (+ CSVs + JSON): the complete cloud
inventory, per-asset compliance standing, a security-lever remediation plan, a
FIPS/encryption posture, EKS **node analysis for Prisma Defender planning**, and
the NIST 800-53 posture — all at **Impact level: Moderate**, for both FedRAMP 20x
and Rev5.

It is the FedRAMP analog of `nonfed_pci_inventory_generator`: the *collector*
(FedPy `cloud-evidence`) does the exhaustive read-only AWS enumeration; *this
tool* is a deterministic, offline transform that joins the inventory to the
compliance evidence and formats the deliverable. It imports FedPy's real types +
scoring, so the two never drift.

> **Assessment aid, not a determination.** Every status is derived from automated
> read-only evidence. A 3PAO makes the final call. Anything with no automated
> evidence is reported **not-assessed / VERIFY** — never assumed compliant.

---

## Contents

- [The two pieces](#the-two-pieces)
- [Prerequisites](#prerequisites)
- [Running it — end to end](#running-it--end-to-end)
  - [Step 1 — authenticate to AWS](#step-1--authenticate-to-aws)
  - [Step 2 — collect (read-only)](#step-2--collect-read-only)
  - [Step 3 — generate the workbook](#step-3--generate-the-workbook)
  - [One-command variant](#one-command-variant)
- [What's in the workbook](#whats-in-the-workbook)
- [Building out a more complete inventory](#building-out-a-more-complete-inventory)
- [GovCloud notes](#govcloud-notes)
- [CLI reference](#cli-reference)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## The two pieces

```
                 read-only AWS APIs (Describe*/List*/Get*)
                              │
   ┌──────────────────────────▼──────────────────────────┐
   │  cloud-evidence collector   (../cloud-evidence)       │  viewer-only IAM +
   │  npm run collect -- --inventory-workbook ...          │  runtime read-only guardrail
   └──────────────────────────┬──────────────────────────┘
                              │ writes out/
   inventory.json  ·  KSI-*.json / FRR-*.json (223 requirements)  ·  control-benchmark.json  ·  signed manifest
                              │
   ┌──────────────────────────▼──────────────────────────┐
   │  fedramp_inventory_export   (this tool)               │  offline, no cloud calls
   │  npm run export -- --run-dir ../cloud-evidence/out    │
   └──────────────────────────┬──────────────────────────┘
                              │ writes out/
   fedramp-inventory-compliance.xlsx  ·  one CSV per sheet  ·  compliance-summary.json
```

- **`../cloud-evidence`** — the collector. Read-only by construction (viewer IAM
  *and* a runtime guardrail that blocks any mutating SDK call). Enumerates every
  resource type and evaluates the 60 KSIs / 223 requirements.
- **`fedramp_inventory_export`** (here) — reads the collector's `out/`, joins
  inventory ↔ compliance, and writes the workbook. Makes **no AWS calls**.

---

## Prerequisites

- **Node 22+** (both projects bundle `tsx`; no global install needed).
- **AWS CLI v2** for authentication (`aws sso login`) or exported STS creds.
- A **read-only-capable AWS session** for the target account. `SecurityAudit` +
  `ViewOnlyAccess` is the baseline; more access surfaces more (see
  [ACCESS-MEMO.md](ACCESS-MEMO.md)). The runtime guardrail keeps the run read-only
  even under a broader role.
- First-time setup in each project:
  ```bash
  cd cloud-evidence && npm install
  cd ../fedramp_inventory_export && npm install
  ```

---

## Running it — end to end

### Step 1 — authenticate to AWS

**SSO (commercial or GovCloud):**
```bash
aws sso login --profile <your-profile>
export AWS_PROFILE=<your-profile>
export AWS_REGION=us-gov-west-1        # or your primary region
```

**Temporary STS keys** (e.g. pasted from the SSO portal):
```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
export AWS_REGION=us-gov-west-1
unset AWS_PROFILE                      # so the keys are used, not a stale profile
```
Verify: `aws sts get-caller-identity` should show the target account.

> **Gotcha:** if both `AWS_PROFILE` and `AWS_ACCESS_KEY_ID` are set, the SDK
> prefers the profile. `unset AWS_PROFILE` when using pasted keys.

### Step 2 — collect (read-only)

The collector reads which regions/providers to scan from a `config.yaml`. A
ready-made GovCloud config is committed at
`../cloud-evidence/config.fedramp-govcloud.yaml` (AWS-only, both gov regions,
Moderate). For a different account, copy it and edit `aws.regions`.

```bash
cd ../cloud-evidence
npx tsx core/orchestrator.ts \
  --config config.fedramp-govcloud.yaml \
  --inventory-workbook \
  --impact-level moderate \
  --out-dir ./out
```

This writes `out/inventory.json`, 221 per-requirement evidence envelopes,
`control-benchmark.json`, and a signed manifest. A dry run (`--dry-run`) prints
the plan and makes no SDK calls.

### Step 3 — generate the workbook

```bash
cd ../fedramp_inventory_export
npm run export -- --run-dir ../cloud-evidence/out --out-dir ./out
```

Output lands in `./out/` (git-ignored):
`fedramp-inventory-compliance.xlsx`, one CSV per sheet, and
`compliance-summary.json`.

### One-command variant

`--collect` runs the collector for you first, then exports:
```bash
npm run export -- --collect --collector-dir ../cloud-evidence --out-dir ./out
```
(Use the explicit steps above when you need a specific `config.yaml` / region set —
`--collect` uses the collector's default `config.yaml`.)

---

## What's in the workbook

Ordered top-to-bottom for flow-down reading (action → where → what → detail):

| # | Sheet | For whom | Contents |
|---|---|---|---|
| 1 | **Executive Summary** | Leadership | KPI tiles, control posture, severity breakdown, top remediation levers, family posture, how-to-read. |
| 2 | **Service Availability** | Sec-eng / Compliance | Per detective/data service (Config, Inspector v2, GuardDuty, Security Hub, Macie, Cost Explorer, Access Analyzer): ENABLED / DISABLED / NOT_AVAILABLE / ACCESS_DENIED, its **impact on the report**, and detail — so a blank lens is explained (service off vs. not in this partition) rather than mistaken for "clean". |
| 3 | **Remediation by Lever** | Sec-eng leads | Failing findings grouped by the tool that fixes them (Prisma/Inspector, GuardDuty, Config, Security Hub, CloudTrail, SIEM, KMS, IAM, Network/WAF, Backup, …) with counts + owner. |
| 4 | **Remediation Plan** | Security engineering | One row per failing finding → lever, priority, affected assets/scope, **action**, NIST controls, suggested owner. The deployment backlog. |
| 5 | **Family Summary** | All | Asset counts + compliance split per resource family. |
| 6 | **Cluster / Grouping Summary** | Platform | Assets attributed to EKS cluster / VPC / account-wide (where things live & flow from). |
| 7 | **FIPS: Crypto Controls** | Compliance / GovCloud | SC-13 / SC-8 / SC-12 / SC-28 rollup with evidence + gaps. |
| 8 | **FIPS: Encryption by Service** | Compliance | Per-service % encrypted, KMS-backed, FIPS-validated, PASS/FAIL/VERIFY. |
| 9 | **FIPS: Encryption Gaps** | Security engineering | Every unencrypted/unknown data store with SC-28 + action. |
| 10 | **FIPS: KMS Key Register** | Security engineering | Keys, multi-region, rotation, CMVP FIPS validation. |
| 11 | **Cluster Node Summary** | Platform / Prisma | Per EKS cluster: version, endpoint, node count, OS/arch mix, node pools, **Defender approach + ≈ Defenders needed**. |
| 12 | **Node Analysis (Defender)** | Platform / Prisma | Per worker node: type, OS (Bottlerocket/AL2), arch, node pool, AZ, FIPS tag, **Defender mode + notes** (DaemonSet, arm64 image, etc.). |
| 13 | **KSI Coverage Matrix** | Leadership / Compliance / 3PAO | All 60 FedRAMP 20x KSIs classified by how each is evidenced — **Automated (cloud config)** / **Hybrid (config + process)** / **Documentation Required** / **External** — with live coverage status, what this report proves, and what still needs manual evidence. The single view of what config proves vs. what you owe as a document. |
| 14 | **Manual & Doc Obligations** | Compliance / GRC | Every requirement (KSI + FRR) that config cannot fully close, each with the **named artifact owed** (Secure Configuration Guide, training review record, restore-test evidence, …) and why it is not automatable. KSIs listed first. |
| 15 | **Requirement Coverage** | Compliance / 3PAO | Per FedRAMP family: what read-only evidence proves + what is not collectable. |
| 16 | **Requirement Status (Mod)** | Compliance | 223 requirements → met / not-met / partial / not-assessed / awareness, each tagged with its assessment type. |
| 17 | **Rev5 Controls (Mod)** | Compliance / 3PAO | NIST 800-53B Moderate baseline (287) benchmark. |
| 18 | **20x Controls (Mod)** | Compliance | 20x-referenced controls benchmark. |
| 19 | **Findings** / **Gaps (Failing)** | Security engineering | Every finding (pass+fail) / failing-only work list. |
| 20 | **Asset Compliance** | All | Every asset's standing (non-compliant / compliant / not-assessed). |
| 21 | **Full Inventory** | All | The complete inventory — one row per asset, all columns (source of truth). |
| 22 | **Inv: <Family>** (one per family) | All | Per-family inventory sheets, pruned to only the columns relevant to that family. |
| 23 | **Data Dictionary** | All | Every inventory column defined: meaning, source, risk-highlighted. |

### How every KSI is covered (assessment types)

FedRAMP 20x KSIs are not uniform. The **KSI Coverage Matrix** sheet classifies all 60
so a red cell is never ambiguous:

| Assessment type | Count* | Meaning | How it closes |
|---|---|---|---|
| **Automated (Cloud Config)** | 24 | Fully provable from read-only cloud config | Status reflects live config; remediate the failing check |
| **Hybrid (Config + Process)** | 20 | Config plumbing is verified here, but full satisfaction also needs a documented/reviewed process | Fix config **and** produce the named review record |
| **Documentation Required** | 15 | Pure governance/process — not observable from any cloud API | Produce the named FedRAMP artifact (tracked in the tracker or SSP) |
| **External** | — | Obligates FedRAMP, an agency, or the 3PAO — not the provider | Informational; no provider action |

\* Counts for a representative GovCloud run. The 60th KSI id (`KSI-CSX-SUM`)
is a meta-aggregator, not a scored indicator.

This is what lets the workbook be the **single periodic-rerun resource** for FedRAMP 20x
Moderate: the automated KSIs are re-proven on every run, and the manual ones are listed
explicitly (with the artifact owed) so nothing silently drops. A KSI that config can't
satisfy is shown as *Documentation Required*, never a misleading *not-met*.

**Styling:** severity/status cells are colour-coded (red/amber/green/grey),
risky inventory cells (unencrypted, public, no-MFA, low-TLS, missing tags) are
highlighted inline, headers are frozen + autofiltered, columns are width-tuned,
and empty-for-this-sheet columns are pruned.

---

## Building out a more complete inventory

The inventory is only as complete as the access it runs under. Empty cells are
**honest** (marked not-assessed / VERIFY / NOT_COLLECTABLE) — never faked. To
surface more, in priority order:

1. **Turn on AWS Config recording** (+ allow `config:SelectResourceConfig`). This
   is the discovery backbone — the single biggest completeness lever. Without it
   the collector falls back to Resource Explorer, which SCPs often limit.
2. **Enable detective services** the collector reads: **Inspector v2**
   (vuln/scan), **GuardDuty** (threat), **Security Hub** (posture), **Macie** (S3
   data classification). Each fills its columns + the matching remediation lever.
3. **Grant the read-only delta** on the runner role: `ssm:GetInventory` +
   `ssm:DescribeInstancePatchStates` (OS/patch), `s3:GetEncryptionConfiguration`
   (S3 encryption), `rds:DescribeDBSnapshots`, `elasticache:*Describe*`,
   `ce:GetCostAndUsage` (cost), `access-analyzer:*`, `kms:GetKeyRotationStatus`.
4. **Tag resources** (`env`, `owner`, `cost-center`, `application`,
   `data-classification`, `baseline`, `eol_date`) — fills the ownership/governance
   columns with zero access change.

> **The collectors for all of the above already exist.** Filling these blanks is a
> matter of **re-running with expanded credentials / enabling the service** — no
> code changes. See **[ACCESS-MEMO.md](ACCESS-MEMO.md)** for the exact per-column
> mapping, grounded in the latest GovCloud run.

Services covered by dedicated depth collectors: EC2/EBS, RDS (+ snapshots), S3,
DynamoDB, Lambda, ELBv2 (+ TLS policy), EKS (+ node analysis), ECR, KMS, Secrets
Manager, IAM (users/roles/keys/MFA), **ElastiCache, Redshift, EFS, SNS, SQS, API
Gateway, Route 53**. Everything else still appears (shallow) via the Config
backbone.

---

## GovCloud notes

- Set `AWS_REGION=us-gov-west-1` (or `-east-1`). ARNs use the `aws-us-gov`
  partition — the collector detects this and synthesizes partition-correct IDs.
- **Not available in (most) GovCloud regions:** Macie, Cost Explorer, CloudFront.
  Their columns stay blank and the run logs `ENOTFOUND` — expected, not an error.
- GovCloud KMS is FIPS 140-2/3 Level-3 HSM-backed; the FIPS sheets reflect that.
- The account this was built against runs a Karpenter/Bottlerocket
  EKS cluster — the Node Analysis sheet is tuned for exactly that (Bottlerocket →
  Defender DaemonSet).

---

## CLI reference

```
npm run export -- [options]

  --run-dir <dir>        FedPy run to read (default: ../cloud-evidence/out)
  --out-dir <dir>        Where to write the workbook + CSVs (default: ./out)
  --collect              Run the collector first, then export
  --collector-dir <dir>  cloud-evidence project dir (default: ../cloud-evidence)
  --providers a,b        With --collect: providers to sweep (e.g. aws,gcp)
  --workbook-name <f>    XLSX file name (default: fedramp-inventory-compliance.xlsx)
  --no-xlsx | --no-csv   Emit only one format
  -h, --help
```

---

## Development

```bash
npm run typecheck      # tsc --noEmit
npm test               # vitest — offline, synthetic fixtures, no AWS
```

Tests exercise the real join, both benchmark framings, the FIPS + node lenses,
the security-lever classifier, and validate the emitted `.xlsx` is a structurally
valid, Excel-openable workbook. Output is deterministic.

```
src/
  load.ts          Read a FedPy run (inventory.json + evidence envelopes).
  join.ts          Core join — assets ↔ findings, requirement rollups, benchmarks.
  attribution.ts   Cluster / VPC / account-wide attribution (where assets live).
  remediation.ts   Security-lever classifier (which tool fixes each finding).
  fips.ts          FIPS / encryption posture (SC-13/8/12/28).
  nodes.ts         EKS node analysis + Prisma Defender planning.
  columns.ts       Column metadata: width, wrap, inline-risk rule, dictionary text.
  tables.ts        Assemble every sheet as a fixed-column table.
  dashboard.ts     Executive summary model.
  writers.ts       Dependency-free CSV + styled multi-sheet XLSX writer.
  collect.ts       Optional --collect seam (runs the collector as a subprocess).
  cli.ts           Entry point.
```

The tool imports FedPy's real modules (`benchmarkControls`, `identifiersMatch`,
`CloudAsset` / `EvidenceFile` types) so scoring can't drift from the collector.
All are pure (`node:fs`/`node:path` only) — no cloud SDK, no spreadsheet dep.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `No inventory.json in …` | The collector didn't run / wrong `--run-dir`. Run Step 2, or point `--run-dir` at the real `out/`. |
| Node Analysis / FIPS sheets empty | Run was collected before those fields existed, or no EKS nodes. Re-collect. |
| Many `ENOTFOUND` in the collect log | Service absent in the partition (Macie/Cost Explorer/CloudFront in GovCloud). Expected. |
| `The security token … is invalid` | Expired STS token — re-auth (Step 1). |
| Providers show `gcp,azure` but AWS empty | `AWS_PROFILE` shadowed your pasted keys — `unset AWS_PROFILE` and re-run. |
| Lots of columns blank | Access-limited run — see [ACCESS-MEMO.md](ACCESS-MEMO.md) and "Building out a more complete inventory". |
| Excel prompts to "repair" the file | Should not happen (validated); if it does, capture the file and open an issue — the writer is hand-rolled OOXML. |
```
