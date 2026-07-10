# PCI DSS v4.0.1 — AWS Asset Inventory, Scope & Evidence Generator

A production-grade, **read-only** tool that enumerates AWS resources across
accounts and regions, analyses PCI **scope** (reachability + IAM graphs), and
produces an auditor-facing **evidence** package for a PCI DSS v4.0.1 assessment.
The output goes directly to a QSA (Qualified Security Assessor) for scope
validation, coverage analysis, and control review.

> **Read-only guarantee.** The tool uses only `Describe*`, `List*`, and `Get*`
> API calls (plus `sts:AssumeRole` for the optional multi-account seam and the
> standard `iam:GenerateCredentialReport` idiom). It never creates, modifies, or
> deletes any AWS resource. Secret **values** (SSM SecureString, Secrets Manager)
> are **never** read — only existence and metadata.

## The three stages

The tool is one package with three subcommands, chained by stable JSON artifacts.
Each stage **augments** the previous one — it never drops or rewrites prior data.

| Stage | Command | Reads | Writes |
|-------|---------|-------|--------|
| **1 — Inventory** | `pci-inventory` | AWS APIs | `output/inventory.json` (+ workbook/CSV) |
| **2 — Scope** | `pci-inventory scope` | `inventory.json` | `output/inventory-scoped.json` (+ scope workbook) |
| **3 — Evidence** | `pci-inventory evidence` | `inventory-scoped.json` | `output/inventory-evidence.json` (+ final QSA workbook) |

```bash
# The full pipeline (single account, ambient SSO credentials):
.venv/bin/pci-inventory                          # Stage 1 → output/inventory.json
.venv/bin/pci-inventory scope --seeds seeds.yaml # Stage 2 → output/inventory-scoped.json
.venv/bin/pci-inventory evidence                 # Stage 3 → output/inventory-evidence.json
```

**Key facts (current build):** version `0.1.0` · inventory schema `1.1.0` ·
**71 columns** per resource · **76 collectors** · Python 3.11+ · deps: boto3,
openpyxl, PyYAML.

---

## Contents

- [Quick start](#quick-start-single-account-sso)
- [Live progress UI](#live-progress-ui)
- [IAM permissions](#iam-permissions)
- [Stage 1 — Inventory](#stage-1--inventory)
- [Stage 2 — Scope analysis](#stage-2--scope-analysis-reachability--iam-graphs)
  - [Declaring seeds](#declaring-seeds-the-one-required-input-for-real-scope)
- [Stage 3 — Evidence enrichment](#stage-3--evidence--control-relevance-enrichment)
- [Multi-account & Organizations](#multi-account--organizations)
- [Region selection](#region-selection--unused-region-detection)
- [Parallelism & rate-limit tuning](#parallelism--rate-limit-tuning)
- [Output: workbook sheets](#output-workbook-sheets)
- [Output: JSON artifacts & schema](#output-json-artifacts--schema)
- [Architecture](#architecture)
- [Development & testing](#development--testing)
- [Research artifacts](#research-artifacts)
- [Scope, assumptions & caveats](#scope-assumptions--caveats)

---

## Quick start (single account, SSO)

```bash
# 1. Install (Python 3.11+)
make install                 # creates .venv and installs runtime deps
# or:  python3 -m venv .venv && .venv/bin/pip install -e .

# 2. Authenticate (your existing read-only SSO role works as-is)
aws sso login --profile my-sso-profile
export AWS_PROFILE=my-sso-profile      # or pass --profile on each command

# 3. Run Stage 1 (read-only; zero extra config)
.venv/bin/pci-inventory                # or: make run
```

That's it — single account, all enabled regions auto-discovered, unused regions
skipped, output in `output/`. A typical single-account run across ~12 in-use
regions collects on the order of 10k–20k resources in a few minutes.

> **Profile gotcha.** `aws sso login --profile X` caches credentials under
> profile `X`, but a bare `pci-inventory` uses boto3's *default* credential chain.
> Either `export AWS_PROFILE=X` (all three stages honour it) or pass `--profile X`
> to each command, or you'll get `Unable to locate credentials`.

---

## Live progress UI

All three stages render an interactive terminal UI on **stderr** when run on an
interactive TTY: a startup banner, a live progress bar for each phase, and a
boxed summary at the end.

The long parallel phase of each stage (Stage 1 collection, Stage 2 gap-fetch,
Stage 3 follow-up findings) drives a **live multi-worker dashboard**:

```
  ⠹ [██████████████████░░░░░░░░] 71%  580/813 units  ·  11204 components  ·  3144 issue(s)  ·  5:12

  workers
   ① ▸ EC2InstanceCollector · us-east-1     0:02
   ② ▸ S3BucketCollector · GLOBAL           0:00
   ③ · idle  47 done
   ...
  recent issues (3144 total)
   • RepositoryPolicyNotFoundException  ecr/ca-central-1  GetRepositoryPolicy
   • AccessDeniedException  macie2/eu-west-1  GetMacieSession
```

- One row per worker thread showing what it is collecting *right now* (active `▸`
  vs `idle · N done`), so you can see the fan-out and spot a stuck worker.
- A streaming **recent issues** pane fed live from the error collector — access
  gaps and quirks appear the instant they're captured, not at the end. Amber =
  expected/benign (access-denied, opt-in region, deprecated service); red =
  unexpected.

**It never interferes with logs or machine use.** The UI is a complete no-op when
output is piped/redirected, or under `--quiet` / `--verbose` / `--no-progress`
(the plain INFO logs carry the story instead). While the dashboard owns the
terminal it captures `WARNING+` log records and flushes them below the frame on
exit, so nothing is lost and the frame is never corrupted. Colour honours
`NO_COLOR` / `TERM=dumb`.

| Flag | Effect |
|------|--------|
| `--no-progress` | Disable the live UI; emit ordinary logs only. |
| `--quiet` | WARNING-level logs only (also disables the UI). |
| `--verbose` | DEBUG logging (also disables the UI so logs aren't clobbered). |

---

## IAM permissions

The tool needs broad **read-only** access. The simplest setup attaches the two
AWS-managed policies:

- **`SecurityAudit`** — read access to security configuration across services.
- **`ViewOnlyAccess`** — list/describe across services.

Those two cover the large majority of calls. A few collectors use actions outside
them (e.g. `account:ListRegions`, `apigateway:GET`, `access-analyzer:*`,
`cloudtrail:GetEventSelectors`, fine-grained `s3:GetBucket*`). A ready-to-use
least-privilege **delta policy** is provided at:

```
iam/pci-inventory-readonly-policy.json
```

Attach `SecurityAudit` + `ViewOnlyAccess` **and** that delta policy for complete
coverage. Anything still denied is captured in the **Errors** sheet rather than
aborting the run, so partial-permission runs are safe and self-documenting.

> **Org/security-admin services** (Control Tower, Macie, Security Hub admin, FMS,
> IAM Identity Center) often can't be read from an ordinary member account and
> will show `AccessDenied` in the Errors output — expected, not a tool failure.

### Optional: cross-account audit role

For the multi-account / Organizations seams, create a read-only role in each
target account (named `PCIInventoryAuditRole` by default, configurable) with the
policies above and a trust policy allowing your central auditing principal to
assume it. An example trust policy is at
`iam/assume-role-trust-policy.example.json`. Your default single-account path does
**not** need this — ambient SSO credentials are used directly.

---

## Stage 1 — Inventory

```bash
pci-inventory                          # ambient credentials / AWS_PROFILE
pci-inventory --profile my-sso-profile # explicit profile
pci-inventory --no-xlsx --no-csv       # JSON handoff artifact only
pci-inventory --verbose                # DEBUG logging to stderr (disables the UI)
```

Enumerates AWS resources across every in-use region and produces the canonical
inventory. Each of the **76 collectors** contributes a normalized record with the
same **71-column** contract. Testable control facts are promoted into typed,
filterable columns (IMDSv2, MFA, access-key age, KMS rotation, TLS minimum
version, cert expiry, log retention, vuln-scan/patch status) rather than buried in
free text. Global services (IAM, Organizations, Route 53, CloudFront, WAF
CLOUDFRONT scope, Shield, S3 namespace) are collected once, labelled `GLOBAL`.

Every run writes, into `output/` (timestamped, account-scoped filenames):

- **Excel workbook** `pci-dss-4.0.1-inventory_<account-or-multi>_<UTC>.xlsx` — the
  primary Stage 1 deliverable.
- **CSV** `…​.csv` — the master inventory, same source of truth.
- **JSON** `…​.json` — timestamped copy of the inventory document.
- **`output/inventory.json`** — the **stable, fixed-name handoff artifact** that
  Stages 2 and 3 consume.

---

## Stage 2 — Scope analysis (reachability + IAM graphs)

```bash
# After Stage 1 has written output/inventory.json:
pci-inventory scope --seeds seeds.yaml          # declare CHD seeds in a file (recommended)
pci-inventory scope --seed-arn arn:aws:rds:…:cluster:payments-aurora   # or ad hoc
pci-inventory scope --no-gap-fetch              # artifact-only (no AWS calls)
```

Stage 2 reads `output/inventory.json`, **expands from human-declared seeds** to
classify every resource as **CDE / connected-to / security-impacting /
out-of-scope / undetermined**, each with a **basis** and a **confidence**
(DETERMINED / CANDIDATE / UNDETERMINED). It writes `output/inventory-scoped.json`
(a superset of `inventory.json` + per-resource `scope` block + the graph
edges/paths), plus a workbook with **Scope Classification**, **Reachability
Paths**, **Segmentation Findings**, **IAM-to-CDE Access**, and **Scope Caveats**
sheets.

What it does:
- **Layer 1 — reachability graph.** A permitted path exists only where the
  **route table ∧ security group ∧ network ACL** all allow it (SG stateful; NACL
  stateless per address-family with ephemeral `1024-65535`, fail-closed when no IP
  is known; same-subnet skips NACL; cross-VPC requires the *same* pcx/tgw on both
  sides). It expands from seeds in both directions, composes **multi-hop** chains
  via transitive closure (a host behind a bastion that reaches the CDE is itself
  connected-to), resolves non-EC2 seeds (RDS/ELB/Lambda) to their ENIs, and records
  the concrete proven path + port. To layer NACLs/routes precisely it re-fetches
  `DescribeNetworkAcls` + `DescribeRouteTables` **read-only** through Stage 1's
  rate-limited, error-capturing infrastructure (multi-account aware);
  `--no-gap-fetch` skips this and lowers path confidence to CANDIDATE, as does any
  path with an assumed leg.
- **Layer 2 — IAM graph.** Resolves principals → policy statements → resource ARNs
  (correct `NotAction`/`NotResource` semantics; wildcard/verb-glob action matching
  like `s3:Get*`/`ec2:*`), intersects with the CDE set, follows the assume-role
  chain (flagging `*`/`:root` trust), and flags principals that can act on a CDE
  resource as security-impacting. This is a **static over-approximation** (no SCP /
  permission-boundary / condition-key / explicit-Deny resolution) — it flags
  candidate access with the granting statement.
- **Layer 3 — heuristics.** Internet exposure, co-location with a seed, name/tag
  signals, and "every data store is a candidate CHD location" (suppressed by
  `data-classification=none`) — emitted as CANDIDATE only, never asserted.
- **Layer 4 — segmentation validation.** For **every** out-of-scope resource
  (human-declared *and* tool-derived), it searches for a permitted relationship to
  the CDE across **network paths AND IAM** — inbound (out-of-scope→CDE)
  contradictions ranked first as **Segmentation Findings**. A resource may carry
  **multiple categories** (e.g. connected-to *and* security-impacting); both shown.

### Declaring seeds (the one required input for real scope)

**PCI scope is driven by where cardholder data (CHD) lives** — a property of your
application and data that **cannot** be read from AWS configuration. So the tool
does **not** originate scope: you declare the CHD-handling resources (the *seeds*)
and it expands from them. **Without seeds, Stage 2 runs in flag-only mode** — it
asserts nothing as in-scope and prints a loud banner.

A ready-to-copy, fully-commented template is in the repo root:

```bash
cp seeds.example.yaml seeds.yaml     # then edit in your real CHD resources
pci-inventory scope --seeds seeds.yaml
```

Three ways to declare seeds (precedence when they conflict: **config file > tags >
CLI flags**):

1. **Seeds file** (`--seeds seeds.yaml`) — most authoritative. Keys:
   `cde_resources`, `cde_networks` (`vpcs`/`subnets`/`cidrs`),
   `connected_declared`, `out_of_scope_declared`.
2. **Tags on the resource** (read from the inventory automatically):
   `pci:cde=true`, `pci:scope=cde|connected|out`, `data-classification=chd|sad`
   (and `data-classification=none` to suppress the candidate-CHD heuristic).
3. **CLI flags** (ad hoc): `--seed-arn`, `--seed-vpc`, `--seed-subnet`,
   `--seed-cidr`, `--out-of-scope` (all repeatable).

`out_of_scope_declared` / `--out-of-scope` does **not** remove a resource from
analysis — it marks it for the **segmentation inverse check** (does a permitted
path back to the CDE exist despite the isolation claim? if so, it's a finding).
Full details in [`docs/scope-seed-and-tagging-convention.md`](docs/scope-seed-and-tagging-convention.md)
and [`research/06-scope-and-segmentation.md`](research/06-scope-and-segmentation.md).

> **Isolation evidence proves isolation, not the absence of CHD.** The tool
> assists and proves connectivity; the human + QSA make the final determination.

---

## Stage 3 — Evidence & control-relevance enrichment

```bash
# After Stage 2 has written output/inventory-scoped.json:
pci-inventory evidence                       # full: map evidence + findings + indicators
pci-inventory evidence --no-findings         # map inventory evidence + indicators only (no AWS calls)
pci-inventory evidence --thresholds t.yaml   # override indicator thresholds
```

Stage 3 reads `output/inventory-scoped.json` (falls back to
`output/inventory.json` with a loud "scope context missing" banner) and produces
the **consolidated QSA workbook** combining inventory + scope + evidence, plus the
final `output/inventory-evidence.json` and a consolidated CSV. It **augments**
prior records — never drops or alters Stage 1/2 data.

What it does:
- **Maps** the inventory's already-collected configuration evidence (the 71
  columns) to **all 12 PCI DSS v4.0.1 requirements** — one evidence sheet per
  requirement domain (Req 01–12), each row traceable to a resource ARN and carrying
  its Stage 2 scope category + confidence.
- **Runs bounded read-only follow-up queries** for the genuinely-new data:
  security-service findings (Security Hub, GuardDuty, Inspector, Access Analyzer,
  Config, Macie) joined to resources by ARN, plus ELBv2 SSL-cipher detail and WAF
  associations for in-scope internet-facing resources. Reuses Stage 1's
  rate-limited, error-capturing infrastructure; a service that isn't enabled is
  recorded, never fatal. `--no-findings` skips all AWS calls.
- **Computes derived indicators** (encryption/MFA/IMDSv2 coverage %, public
  exposure, unencrypted/stale-credential/expiring-cert lists, CloudTrail/Config
  coverage, log-retention flags, overly-permissive IAM) **overall and per scope
  category**, with conventional configurable thresholds (stale credential > 90d;
  cert expiry warn < 30d / notice < 90d; log retention < 365d for 10.5.1).

**These indicators ASSIST assessment — they are NOT compliance determinations.**
The QSA makes all determinations. Requirement 9 (physical) and process controls
are AWS shared-responsibility / out-of-band and are noted, not asserted. See
[`research/08-evidence-requirement-mapping.md`](research/08-evidence-requirement-mapping.md).
The workbook's **QSA Notes** sheet documents how scope was determined, the
limitations, and the read-only attestation.

---

## Multi-account & Organizations

Provide a config file listing accounts (named profiles and/or assume-role):

```bash
pci-inventory --config examples/accounts.example.yaml
```

Or run from a management / delegated-admin account and enumerate **active** member
accounts, assuming the configured read-only role in each:

```yaml
# config.yaml
organizations:
  - profile: org-management-sso
    role_name: PCIInventoryAuditRole
    exclude_account_ids: ["999988887777"]
```

```bash
pci-inventory --config config.yaml
```

Every record is tagged with its `account_id` and `account_alias`. The
`organizations` key is a **list**, so additional organizations can be added later
without structural change. Stages 2 and 3 reuse the same `--config` for their
multi-account read-only calls; accounts without a reachable session degrade to
artifact-only work with a recorded note.

---

## Region selection & unused-region detection

Enabled regions are auto-discovered per account (never hardcoded). A cheap
indicator probe (EC2 instances, non-default VPCs, ENIs, RDS, Lambda) decides
whether each region is *in use*; regions with no footprint are **recorded but
skipped** for full collection. The probe **fails open** — if an indicator call
errors, the region is included rather than silently dropped.

```bash
pci-inventory --regions us-east-1 us-west-2     # allowlist
pci-inventory --exclude-regions ap-south-1      # subtract
pci-inventory --all-regions                     # force full incl. empty
pci-inventory --include-empty-regions           # collect empty too
```

The **Regions Coverage** sheet documents every enabled region, its in-use
determination, the triggering indicator, and included/excluded status.

---

## Parallelism & rate-limit tuning

Work units `(account × region × collector)` run on a bounded thread pool. Each
worker creates its own boto3 clients (clients are not thread-safe). Three layers
guard against API throttling:

1. **boto3 adaptive retries** (`retries={'mode':'adaptive', ...}`).
2. A **global token bucket** capping aggregate request rate, backing off on
   throttling responses.
3. **Per-service concurrency caps** — hard-throttling services (IAM,
   Organizations, Config, CloudTrail, API Gateway) run at low concurrency. These
   gates are **per-thread reentrant**, so a collector that makes a nested gated
   call while iterating a paginated result (e.g. Organizations
   `list_policies` → `describe_policy`) cannot self-deadlock.

Tune via flags or config:

```bash
pci-inventory --max-workers 8
```

```yaml
concurrency:
  max_workers: 12
  retries_max_attempts: 10
  hard_throttle_cap: 2
  medium_throttle_cap: 6
  tokens_per_second: 40.0
  bucket_capacity: 80.0
```

Throttling events and the final count are logged and reported on the Cover sheet.

---

## Output: workbook sheets

### Stage 1 — inventory workbook

| Sheet | Contents |
|-------|----------|
| **Cover** | Generation date/time (UTC), tool version, accounts/orgs scanned, regions included/excluded, totals by service, risk counts (public-facing / unencrypted / logging-disabled), and data-collection caveats. |
| **All Components** | The master inventory — one row per resource, all 71 contract columns. Frozen header, autofilter, risk highlighting. |
| **Compute / Network / Storage / Database / IAM / Security / Logging / Edge-Exposure / Management / Messaging** | Per-domain filtered views of the same source of truth. Tabs appear only when they contain rows. |
| **Regions Coverage** | Every enabled region per account: enabled, in-use, status, the indicator that triggered the determination, and probe detail. |
| **PCI Requirement Coverage** | Each of the 12 PCI DSS v4.0.1 requirements mapped to the inventory columns/signals that evidence it, with a Strong / Partial / Not-collectable verdict and an honest statement of what cannot be evidenced read-only. |
| **Errors** | Every captured per-call failure (AccessDenied, throttling, unsupported region, no-such-config, …) so missing data is **visible and explained** — distinguishing "not present" from "could not read." |
| **Data Dictionary** | Every column defined: name, definition, type, example, source API, mandatory/best-effort, and supporting PCI requirement(s). |

### Stage 2 — scope workbook
**Scope Classification** · **Reachability Paths** · **Segmentation Findings** ·
**IAM-to-CDE Access** · **Scope Caveats**.

### Stage 3 — evidence workbook (final QSA deliverable)
Per-requirement **Req 01 … Req 12** evidence sheets · **PCI Requirement Mapping** ·
**Findings & Indicators** · **QSA Notes**.

**Formatting:** frozen header rows, bold colored headers, autofilters, sensible
column widths, wrapped long text, ISO 8601 UTC dates, booleans as `Yes`/`No`, and
conditional red highlighting for risk-relevant fields.

**Sentinels** distinguish empty-because-inaccessible from genuinely-absent:
`N/A` (not applicable), `ACCESS_DENIED` (call denied), `NOT_COLLECTED` (not
gathered this run), `NOT_COLLECTABLE` (control real but not observable from
read-only AWS APIs — in-guest/process/physical), `UNKNOWN` (a determination could
not be made because the deciding call failed), blank (genuinely unset), and
`UNDETERMINED — pending Stage 2` (scope only, before Stage 2 runs).

---

## Output: JSON artifacts & schema

Three stable, documented JSON documents, each a superset of the prior. Stages 2
and 3 only **add** keys; they never remove or rename earlier keys. Versions are
bumped on any contract change.

| Artifact | Added by | Version key |
|----------|----------|-------------|
| `output/inventory.json` | Stage 1 | `schema_version` = **1.1.0** |
| `output/inventory-scoped.json` | Stage 2 | `scope_schema_version` = 1.0.0 (+ per-resource `scope` block + `scope_analysis`) |
| `output/inventory-evidence.json` | Stage 3 | `evidence_schema_version` = 1.0.0 (+ per-resource `evidence` block + `evidence_analysis`) |

```jsonc
// output/inventory.json (Stage 1)
{
  "schema_version": "1.1.0",
  "generated_at_utc": "2026-06-30T00:00:00Z",
  "collector_version": "0.1.0",
  "command": { "flags": { ... } },
  "accounts_scanned": [ { "account_id": "...", "alias": "...", "via": "default|profile:..|assume-role:.." } ],
  "regions_coverage": [ { "account_id": "...", "region": "...", "enabled": true,
                          "in_use": true, "status": "included|excluded",
                          "indicator": "...", "probe_detail": { ... } } ],
  "resources": [ { /* the 71 contract columns, see below */ } ],
  "errors": [ { "account_id": "...", "region": "...", "service": "...",
                "operation": "...", "resource_id": "...", "error_code": "...",
                "message": "...", "timestamp_utc": "..." } ],
  "stats": { "totals_by_type": {...}, "totals_by_service": {...},
             "total_resources": 0, "risk_counts": {...},
             "throttling_events": 0, "duration_seconds": 0, "error_count": 0 }
}
```

### Per-resource record (71 columns)

Identity & description: `arn`, `resource_id`, `account_id`, `account_alias`,
`region`, `availability_zone`, `service`, `resource_type`, `name`,
`description_purpose`, `environment`, `owner_team`.

Scope (Stage 1 placeholder, filled by Stage 2): `pci_scope`, `pci_scope_basis`,
`data_classification`.

Platform/software: `os_platform_engine`, `os_platform_version`, `software_app`,
`software_version`, `is_bespoke_software`.

Exposure/network: `public_exposed`, `exposure_basis`, `private_ips`, `public_ips`,
`dns_names`.

**Typed control facts (re-audit R2)** — promoted out of free text so a QSA can
filter directly: `imdsv2_required`, `mfa_enabled`, `mfa_type`,
`access_key_age_days`, `tls_min_version`, `cert_expiry_date`,
`kms_rotation_enabled`, `kms_rotation_period_days`, `log_retention_days`,
`vuln_scan_status`, `vuln_findings_summary`, `patch_compliance`, `backup_config`,
plus encryption/logging detail fields.

**Handoff data for Stages 2/3:**
- **`relationships`** — typed adjacency (EC2 → enis/ebs/security_groups/subnet/vpc/
  instance_profile; LB → listeners/target_groups/certificates; SG →
  ingress_rules/egress_rules/referenced_sgs; subnet → route_table/nacl/vpc). Stage
  2 builds its reachability graph from this.
- **`iam_policy_data`** — raw IAM/identity data: `principal_type`, managed/inline
  policies (full documents), trust policy/principals, resource-based policies (S3,
  KMS, Lambda, SQS/SNS, Secrets, ECR, …), permissions boundary, access-key metadata
  (id/status/age/last-used — **never** secret material), MFA devices, and captured
  `scope_tags`. Stage 2 builds its IAM graph from this. (Stage 1 uses a single
  paginated `GetAccountAuthorizationDetails` + credential report.)

Provenance: `notes`, `collection_timestamp`, `collector_version`, `source_calls`.

The complete column contract is in
[`research/02-column-schema.md`](research/02-column-schema.md) and the workbook's
Data Dictionary sheet.

---

## Architecture

```
src/pci_inventory/
  cli.py            # Stage 1 CLI; dispatches `scope`/`evidence` subcommands
  config.py         # AppConfig + YAML/JSON loader (accounts, orgs, tuning)
  auth.py           # session mgmt: ambient/SSO default + STS assume-role seam
  regions.py        # enabled-region discovery, indicator probe, coverage report
  concurrency.py    # token bucket, per-service reentrant gate, error collector, work pool
  orchestrator.py   # builds & runs Stage 1 work units, assembles RunResult
  progress.py       # interactive UI: banner, live multi-worker dashboard, summary box
  utils.py          # sentinels, time/normalization helpers, policy analysis, logging
  schema/models.py  # ResourceRecord dataclass + 71-column COLUMNS contract + domains
  collectors/       # base.py + one module per domain; 76 collectors via @register
    compute network edge storage database iam security logging_mon management messaging extra
  output/           # result.py, json_writer.py, csv_writer.py, workbook.py, render.py
  scope/            # Stage 2: models, seeds, artifact, gapfetch, netprims,
                    #   reachability (L1), iamgraph (L2), classifier (L3+4), runner, workbook, cli
  evidence/         # Stage 3: models, loader, mapping, findings, indicators, runner, workbook, csv_writer, cli
```

**Design seams:** the `ResourceRecord` model is the column contract; collectors
register via a decorator so new services drop in without touching the
orchestrator; the JSON artifacts are additive-only; Stages 2/3 reuse Stage 1's
`concurrency` and `auth` infrastructure and the `progress` UI unchanged.

---

## Development & testing

```bash
make dev-install     # runtime + dev deps (pytest, ruff, mypy) editable
make test            # offline tests (no AWS needed)
make lint            # ruff
make type            # mypy
```

The offline test suite (**67 tests**, all AWS-free using synthetic fixtures)
covers the schema contract and all three writers, Stage 2 scope logic (incl. the
re-audit cases: NACL deny, cross-VPC peering, multi-hop bastion, IAM
NotAction/wildcards), Stage 3 evidence mapping, the concurrency gate (nested
acquire must not deadlock; cross-thread cap enforced), the progress UI (no-op when
not a TTY; frame bounded to the terminal; ANSI-safe clipping), and seeds-file
parsing (including empty/half-filled templates). Output is deterministic across
`PYTHONHASHSEED`.

```bash
tests/test_pipeline_offline.py   tests/test_scope_offline.py   tests/test_scope_reaudit.py
tests/test_evidence_offline.py   tests/test_progress.py        tests/test_concurrency.py
```

---

## Research artifacts

The Phase 0 analysis and per-stage design records live in `research/`:

- [`01-pci-inventory-requirements.md`](research/01-pci-inventory-requirements.md) — what 12.5.1 and adjacent requirements mandate.
- [`02-column-schema.md`](research/02-column-schema.md) — the complete column contract.
- [`03-service-coverage-matrix.md`](research/03-service-coverage-matrix.md) — every service → API call, pagination, throttle profile, regional vs global, IAM permission.
- [`04-pci-requirement-evidence-mapping.md`](research/04-pci-requirement-evidence-mapping.md) · [`05-reaudit-gap-analysis.md`](research/05-reaudit-gap-analysis.md) — Stage 1 re-audit (schema 1.1.0).
- [`06-scope-and-segmentation.md`](research/06-scope-and-segmentation.md) · [`07-stage2-reaudit-gap-analysis.md`](research/07-stage2-reaudit-gap-analysis.md) — Stage 2 design + re-audit.
- [`08-evidence-requirement-mapping.md`](research/08-evidence-requirement-mapping.md) — Stage 3 evidence↔requirement mapping.

> **Filename note:** research files are numbered in creation order across sessions,
> not by stage (Stage 2 = `06`, Stage 3 = `08`).

---

## Scope, assumptions & caveats

- **Scope comes from seeds, not the tool.** Stage 1 `pci_scope` is a placeholder;
  Stage 2 classifies from human-declared seeds. Without seeds, Stage 2 flags
  candidates only and asserts nothing in-scope.
- **No cardholder-data discovery.** No object/content scanning.
  `data_classification` comes from tags only; otherwise `NOT_COLLECTED`. Isolation
  evidence proves isolation, **not** the absence of CHD.
- **Secret hygiene.** SecureString/Secrets values are never read — existence and
  metadata only. KMS captures policy/rotation metadata, never key material.
- **IAM analysis is a static over-approximation** — no SCP / permission-boundary /
  condition-key / explicit-Deny resolution; it flags candidate access with the
  granting statement, not effective access.
- **Not observable read-only** (recorded as `NOT_COLLECTABLE`, never silently
  blank): in-guest anti-malware (Req 5), OS time-sync (10.6), file-integrity
  monitoring (11.5.2), in-guest hardening (Req 2).
- **Shared responsibility / out-of-band:** Req 9 physical (AWS Artifact AOC);
  process/documentation controls (most of Req 12); ASV external scans and pen tests
  (11.3/11.4).
- **POI / physical devices (9.5.x)** are out of tool scope for cloud-only
  assessments — flagged, not collected.
- **On-prem hosts** reachable via Direct Connect / VPN are recorded as connectivity
  objects, but the hosts themselves are not enumerable by AWS APIs.
- **Deprecated services** the installed SDK no longer knows (e.g. QLDB, end of
  support 2025-07-31) are recorded once as a benign skip, never fatal.
- **DocumentDB / Neptune** are collected via the RDS API (engine filter), as AWS
  exposes them there. **Trusted Advisor / Health** require Business/Enterprise
  Support; otherwise `NOT_COLLECTED` with a note.

Assumptions that could affect scope correctness are labelled `[ASSUMPTION]` in the
research docs and surfaced in the Cover-sheet caveats.
```
