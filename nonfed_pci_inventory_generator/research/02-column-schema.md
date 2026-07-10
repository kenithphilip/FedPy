# 02 — Inventory Column Schema (the data contract)

> This is the **contract** the inventory must fulfill. Every column below is emitted for every
> record (value, or one of the explicit sentinels). Collectors normalize their service-specific
> fields into these columns. Stages 2 and 3 add columns but **must not remove or rename** these.
>
> **Sentinels** (so "empty because inaccessible" ≠ "genuinely absent"):
> - `N/A` — attribute does not apply to this resource type.
> - `ACCESS_DENIED` — call returned AccessDenied / authorization failure.
> - `NOT_COLLECTED` — not gathered this run (out of read-only reach, or best-effort skipped).
> - `NOT_COLLECTABLE` — control is real but NOT observable from read-only AWS APIs (in-guest /
>   process / physical). Distinct from `NOT_COLLECTED`. *(added in schema 1.1.0)*
> - `UNKNOWN` — a determination (e.g. public exposure) could not be made because the deciding
>   call failed. *(added in schema 1.1.0)*
> - `UNDETERMINED — pending Stage 2` — deferred to a later stage (only `pci_scope`).
> - empty string + note — genuinely absent / not set.
>
> **Booleans** render as `Yes`/`No` in the workbook; stored as JSON booleans in `inventory.json`.
> **Dates** are ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).

> ### Schema 1.1.0 re-audit addendum
> The base table below is the original 43-column contract. The re-audit (see `research/05`) added
> the following **typed control columns** (full definitions in the workbook's Data Dictionary
> sheet, which is generated from `schema/models.py` — the authoritative source):
> `imdsv2_required`, `metadata_hop_limit`, `eol_status`, `patch_compliance`, `vuln_scan_status`,
> `vuln_findings_summary`, `anti_malware_status`, `publicly_shared`, `public_access_block`,
> `segmentation_role`, `kms_rotation_enabled`, `kms_rotation_period_days`, `key_origin_manager`,
> `tls_min_version`, `cert_expiry_date`, `cert_key_algo`, `log_retention_days`,
> `change_detection_monitored`, `time_sync_source`, `deletion_protection`,
> `auto_minor_version_upgrade`, `mfa_enabled`, `mfa_type`, `access_key_age_days`,
> `last_used_age_days`, `is_root_account`, `password_policy_summary`, `iam_db_auth`. The
> `backup_retention` column was split into `backup_config` + numeric `log_retention_days`. Total: **71 columns.**

---

## Column table

| # | Column (json key) | Definition | Type | Example | Source API / field | Mandatory? | PCI req(s) |
|---|-------------------|------------|------|---------|--------------------|------------|------------|
| 1 | `arn` | Canonical AWS ARN (primary unique key). Synthesized if service has no native ARN. | str | `arn:aws:ec2:us-east-1:111122223333:instance/i-0abc` | per-service | **Mandatory** | 12.5.1 |
| 2 | `resource_id` | Native resource id (short). | str | `i-0abc123` | per-service | **Mandatory** | 12.5.1 |
| 3 | `account_id` | 12-digit AWS account. | str | `111122223333` | STS GetCallerIdentity / config | **Mandatory** | 12.5.1, A1 |
| 4 | `account_alias` | IAM account alias or configured friendly name. | str | `acme-prod` | `iam:ListAccountAliases` | Best-effort | 12.5.1 |
| 5 | `region` | AWS region; `GLOBAL` for global services. | str | `us-east-1` / `GLOBAL` | session/config | **Mandatory** | 12.5.1 |
| 6 | `availability_zone` | AZ if resource is zonal. | str | `us-east-1a` | per-service | Best-effort | 12.5.1 |
| 7 | `service` | AWS service namespace. | str | `ec2` | collector | **Mandatory** | 12.5.1 |
| 8 | `resource_type` | Specific type within service. | str | `ec2:instance` | collector | **Mandatory** | 12.5.1, 2.2.1 |
| 9 | `name` | Name tag or service name field. | str | `web-01` | tags `Name` / per-service | **Mandatory** | 12.5.1 |
| 10 | `description_purpose` | Function/use/role — the 12.5.1 description. From `Description`/`purpose` tag/service field; else derived from type. | str | `Internet-facing app LB` | tags / per-service | **Mandatory** | **12.5.1** |
| 11 | `environment` | Env from tags (`environment`/`env`/`stage`). | str | `prod` | tags (configurable keys) | Best-effort | 12.5.2 |
| 12 | `owner_team` | Owner/team from tags (`owner`/`team`/`cost-center`). | str | `payments` | tags | Best-effort | 12.5.1 |
| 13 | `pci_scope` | Scope classification. **Stage 1 placeholder.** | enum | `UNDETERMINED — pending Stage 2` | Stage 2 | **Mandatory** (placeholder) | 12.5.1, 12.5.2 |
| 14 | `pci_scope_basis` | Reason/evidence for classification. Empty in Stage 1. | str | (empty) | Stage 2 | Mandatory (placeholder) | 12.5.2 |
| 15 | `data_classification` | Data sensitivity if inferable from tag/service semantics; else `NOT_COLLECTED`. | str | `chd` / `NOT_COLLECTED` | tags `data-classification` | Best-effort | 3.1, 3.2.1 |
| 16 | `os_platform_engine` | OS / platform / DB engine. | str | `Amazon Linux 2` / `postgres` | per-service (Platform, Engine, runtime) | Best-effort | 2.2.1, 12.3.4 |
| 17 | `os_platform_version` | Version of the above. | str | `14.7` | per-service | Best-effort | 6.3.2, 12.3.4 |
| 18 | `software_app` | Bespoke/app identifier (function name, image, platform). | str | `orders-api` | per-service / tags | Best-effort | **6.3.2** |
| 19 | `software_version` | App / image / package version. | str | `sha256:…` / `1.4.2` | per-service | Best-effort | **6.3.2**, 12.3.4 |
| 20 | `is_bespoke_software` | Whether component runs custom/bespoke code (heuristic: Lambda, ECS/EKS workloads, Beanstalk). | bool | `Yes` | derived | Best-effort | 6.3.2 |
| 21 | `public_exposed` | Internet-reachable (public IP, internet-facing LB, public S3, public API/CloudFront, SG open to 0.0.0.0/0). | bool | `Yes` | derived (see `exposure_basis`) | **Mandatory** | 1.2, 1.3, 1.4 |
| 22 | `exposure_basis` | Concrete reason(s) for `public_exposed`. | list[str] | `["public-ip","sg 0.0.0.0/0:443"]` | derived | **Mandatory** | 1.3.x |
| 23 | `private_ips` | Private IPv4/IPv6 addresses. | list[str] | `["10.0.1.4"]` | per-service / ENI | Best-effort | 1.2 |
| 24 | `public_ips` | Public IPs / EIPs. | list[str] | `["52.1.2.3"]` | per-service / ENI | Best-effort | 1.3 |
| 25 | `dns_names` | Public/private DNS, endpoints, FQDNs. | list[str] | `["api.acme.com"]` | per-service | Best-effort | 1.2 |
| 26 | `encryption_at_rest` | Encrypted at rest. | tri-bool | `Yes`/`No`/`N/A` | per-service (Encrypted, KmsKeyId, SSE) | **Mandatory** where applicable | 3.5, 3.6 |
| 27 | `encryption_at_rest_detail` | KMS key ARN / SSE algorithm / mode. | str | `aws:kms arn:…key/…` | per-service | Best-effort | 3.6, 3.7 |
| 28 | `encryption_in_transit` | TLS/in-transit enforced (LB TLS listener, RDS SSL, S3 TLS policy, endpoint). | tri-bool | `Yes`/`No`/`N/A` | per-service | Best-effort | 4.2.1, 2.2.7 |
| 29 | `encryption_in_transit_detail` | TLS policy / min version / cert ref. | str | `ELBSecurityPolicy-TLS13-1-2` | per-service | Best-effort | 4.2.1 |
| 30 | `logging_enabled` | Resource-level logging on (flow logs, access logs, trail, CW logs). | tri-bool | `Yes`/`No`/`N/A` | per-service | **Mandatory** where applicable | 10.2, 10.3 |
| 31 | `logging_detail` | What logging + destination. | str | `flowlogs→cwl /vpc/flow` | per-service | Best-effort | 10.2 |
| 32 | `backup_retention` | Backup enabled / retention period. | str | `7 days` / `No` | per-service | Best-effort | 10.5.1, 12.10 |
| 33 | `creation_date` | Resource creation time (UTC). | datetime | `2025-01-04T12:00:00Z` | per-service | Best-effort | 12.5.1 (currency) |
| 34 | `last_modified_activity` | Last mod/config-change/activity time (UTC). | datetime | `2026-06-01T09:30:00Z` | per-service | Best-effort | 12.5.1, 8.2.6 |
| 35 | `state_status` | Lifecycle state. | str | `running` / `available` | per-service | **Mandatory** | 12.5.1 |
| 36 | `tags` | All tags as key→value map. | dict | `{"Name":"web-01"}` | per-service tags | **Mandatory** | 12.5.2 |
| 37 | `tag_completeness` | Fraction/flag of required governance tags present (configurable required set). | str | `3/4 (missing: owner)` | derived | Best-effort | 12.5.2 |
| 38 | `relationships` | Typed references to related resources (see §Relationship model). | dict[str,list[str]] | `{"security_groups":["sg-…"]}` | per-service | **Mandatory** where applicable | 12.5.2, 1.2 |
| 39 | `iam_policy_data` | Raw IAM/identity policy data for principals & resource policies (for Stage 2 IAM graph). | dict | `{...}` | IAM/STS/resource policy | **Mandatory** for IAM & policy-bearing resources | 7.x, 8.x |
| 40 | `notes` | Free-text collector notes / caveats / partial-collection reasons. | str | `flow logs: ACCESS_DENIED` | collector | Best-effort | 12.5.1 |
| 41 | `collection_timestamp` | UTC time this record was collected. | datetime | `2026-06-29T00:00:00Z` | runtime | **Mandatory** | 12.5.1 (currency) |
| 42 | `collector_version` | Tool version that produced the record. | str | `0.1.0` | runtime | **Mandatory** | traceability |
| 43 | `source_calls` | API calls used to build the record (audit trail). | list[str] | `["ec2:DescribeInstances"]` | collector | Best-effort | traceability |

> **Risk-highlight columns** (conditional formatting in the workbook): `public_exposed=Yes`,
> `encryption_at_rest=No`, `encryption_in_transit=No`, `logging_enabled=No`, MFA-disabled (IAM),
> cert/key nearing expiry (`encryption_in_transit_detail`/Security domain), access-key age.

---

## Relationship model (column 38, `relationships`)

Typed adjacency captured in Stage 1 so Stage 2 can build reachability + IAM graphs without
re-calling AWS. Keys are stable; values are lists of ARNs/ids.

| Source resource | Relationship keys captured |
|-----------------|----------------------------|
| EC2 instance | `enis`, `ebs_volumes`, `security_groups`, `subnet`, `vpc`, `iam_instance_profile`, `image_id`, `key_name` |
| ENI | `subnet`, `vpc`, `security_groups`, `attached_to`, `private_ips`, `public_ip` |
| EBS volume | `attached_instances`, `kms_key`, `snapshots` |
| Security group | `vpc`, `ingress_rules`, `egress_rules`, `referenced_sgs` |
| Subnet | `vpc`, `route_table`, `nacl`, `availability_zone` |
| Route table | `vpc`, `subnets`, `routes` (→ igw/nat/peering/tgw/eni) |
| VPC | `subnets`, `peering_connections`, `tgw_attachments`, `endpoints`, `igws`, `nat_gateways`, `flow_logs` |
| Load balancer | `listeners`, `target_groups`, `targets`, `security_groups`, `subnets`, `vpc`, `certificates` |
| Target group | `targets`, `vpc`, `load_balancer` |
| Lambda | `vpc`, `subnets`, `security_groups`, `execution_role`, `layers`, `event_sources` |
| RDS/Aurora | `subnet_group`, `security_groups`, `vpc`, `kms_key`, `parameter_group`, `cluster_members` |
| S3 bucket | `kms_key`, `policy_principals`, `replication_targets` |
| IAM role | `attached_policies`, `inline_policies`, `trust_principals`, `instance_profiles` |
| IAM user | `groups`, `attached_policies`, `inline_policies`, `access_keys`, `mfa_devices` |
| IAM group | `members`, `attached_policies`, `inline_policies` |
| KMS key | `aliases`, `key_policy_principals`, `grants` |
| VPC endpoint | `vpc`, `subnets`, `security_groups`, `service_name`, `policy` |
| TGW attachment | `tgw`, `vpc`, `peering` |

---

## IAM policy data model (column 39, `iam_policy_data`)

Captured raw for Stage 2's IAM graph. Per principal/resource:
- `principal_type` (user/role/group/service)
- `attached_managed_policies` (ARNs)
- `inline_policies` (name → policy JSON document)
- `assume_role_policy` / `trust_policy` (for roles)
- `resource_based_policy` (for S3/KMS/Lambda/SQS/SNS/Secrets/ECR/API GW)
- `permissions_boundary`
- `access_keys` (id, status, create date, last-used — **never** secret material)
- `mfa_devices`, `last_activity`

> Only policy **metadata and documents** are captured — never secret values, key material, or
> CHD. SecureString/Secrets values are recorded as existence + metadata only.

---

## JSON artifact (`output/inventory.json`) top-level schema

```jsonc
{
  "schema_version": "1.0.0",
  "generated_at_utc": "2026-06-29T00:00:00Z",
  "collector_version": "0.1.0",
  "command": { "regions": [...], "accounts": [...], "flags": {...} },
  "accounts_scanned": [ { "account_id": "...", "alias": "...", "via": "default|assume-role" } ],
  "regions_coverage": [ { "region": "...", "enabled": true, "in_use": true,
                          "indicator": "ec2:instances>0", "status": "included|excluded" } ],
  "resources": [ { <every column above> } ],
  "errors": [ { "account_id": "...", "region": "...", "service": "...",
                "operation": "...", "error_code": "...", "message": "...",
                "timestamp_utc": "..." } ],
  "stats": { "totals_by_type": {...}, "throttling_events": 0, "duration_seconds": 0 }
}
```

`schema_version` is bumped if Stage 2/3 change the contract; Stages 2/3 only **add** keys to each
resource (`pci_scope` populated, evidence blocks), never remove Stage 1 keys.
