# 05 — Re-Audit Gap Analysis & Remediation Plan

> Synthesis of four parallel audits (column schema vs all 12 requirements; AWS
> API/service coverage; implementation correctness; per-requirement evidence
> mapping in `04`). This is the plan of record for upgrading Stage 1 from a
> 43-column enumeration tool to a QSA-grade inventory that supports live control
> checks across all 12 requirements. **No code has been changed yet** — this
> awaits your review.

## Headline conclusions

1. **The schema is built for enumeration + scope-handoff, not live control validation.** It is strong on Req 1 and 12, but collapses individually-testable control facts (TLS version, MFA, key rotation, log retention, IMDSv2) into free-text "detail" blobs a QSA cannot filter, pivot, or count. **The single highest-value change is promoting testable facts out of the blobs into typed columns.**
2. **The coverage matrix overstates what the code implements.** ~20 describe/get calls the matrix promises are never made (RDS snapshots, ELBv2 attributes/SSL policies/target groups, CloudTrail event selectors, Config conformance/compliance, S3 ACL/account-PAB, KMS grants, Org OU tree/SCP bodies, security-service findings, etc.).
3. **There is a class of silent-truncation bugs** — single-shot `.call()` on APIs that paginate (SQS, Kinesis, MQ, EventBridge rules, apigatewayv2, wafv2, Org SCPs, detective, memorydb, timestream, qldb). For a compliance inventory, silent undercount is the most damaging defect class.
4. **Several correctness issues create false negatives on exposure** (substring policy-matching; region probe fails closed on throttle; S3 AccessDenied treated as "not public"; RDS cluster `PubliclyAccessible` dead code; hard-coded `public_exposed=False` on snapshots without checking share attributes).
5. **Read-only safety: PASS.** No mutating calls; only `sts:AssumeRole` + the standard `GenerateCredentialReport` idiom (note it in the Cover caveats).

---

## A. CORRECTNESS BUGS — fix regardless of scope expansion

Ordered by severity. (file references approximate.)

### Critical — silent result truncation (single-shot on paginated APIs)
- `messaging.py` — `list_queues` (SQS, >1000 lost), `list_streams` (Kinesis, >100), `list_brokers` (MQ). Route through `ctx.call.paginate`.
- `messaging.py` / `logging_mon.py` — EventBridge `list_rules` truncates **and** only enumerates the **default** bus; must loop buses (`list_event_buses` → `list_rules(EventBusName=...)`), both paginated.
- `security.py` — `detective list_graphs`.
- `database.py` — `memorydb describe_clusters`, `timestream list_databases`, `qldb list_ledgers`.
- `edge.py` — `apigatewayv2 get_apis` (>25), `wafv2 list_web_acls` (>100, `NextMarker`).
- `management.py` — `organizations list_policies` (SCPs).
- **Fix:** convert each to `ctx.call.paginate` (it already has a safe single-shot fallback when `can_paginate()` is False) or token-loop.

### High
- **Region probe fails closed (M6).** `regions.py` — a throttle/AccessDenied during probing returns empty → region marked "no resources" → **excluded**. A transient throttle silently drops an entire active region. **Fix:** fail *open* — if any probe call recorded an error, treat region as in-use / `indeterminate`, never exclude.
- **Throttle gate not applied to single-shot calls (L4).** `concurrency.py` — `gate_for(service)` is acquired only in `paginate`, not in `call`. The bulk of IAM's per-principal calls are single-shot, so the hard-cap of 2 is **not enforced** on the most throttle-prone service. **Fix:** acquire the gate inside `CallContext.call` too.
- **Public-policy detection by substring (H3).** `compute.py` (lambda/ecr), `messaging.py` (sns/sqs). Misses `{"AWS":["*"]}` list form and cross-account `:root`; false-positives when a restrictive `Condition` scopes a `"*"` principal. **Fix:** parse JSON, evaluate `Effect=Allow` + wildcard principal + absence of scoping `Condition`; prefer AWS-computed status where it exists (S3 `GetBucketPolicyStatus` is the model). Capture a caveat when a Condition is present.
- **EBS/RDS snapshot + AMI public-sharing not checked.** Hard-coded `public_exposed=False`. **Fix:** `ec2:DescribeSnapshotAttribute(createVolumePermission)`, `ec2:DescribeImageAttribute(launchPermission)`, `rds:DescribeDBSnapshotAttributes(restore=all)`; never assert `False` without the call — use `UNKNOWN` otherwise.

### Medium
- **RDS cluster `PubliclyAccessible` is dead code (M1).** `describe_db_clusters` doesn't return it; always False. Derive from member instances or drop + note.
- **S3 AccessDenied treated as not-public / encrypted (M3, M4).** When `GetBucketPolicyStatus`/`GetPublicAccessBlock`/`GetBucketEncryption` error, the record silently becomes not-exposed / encrypted=True. **Fix:** set `ACCESS_DENIED` sentinel + note; never assert an unverified control.
- **Per-item builders outside `collect_each` (M5).** EKS and DynamoDB loops `KeyError` on a malformed item drop the rest of that service's results in the region. **Fix:** wrap each item.
- **Management account omitted under org discovery (M7).** Origin/management account's own ambient session is never added. **Fix:** include it, deduped by id.
- **CloudTrail `includeShadowTrails=False` (matrix/A2).** Can hide the org trail in member accounts → false "single-region/no trail." **Fix:** include shadow trails and dedup by `TrailARN`.
- **"TOTAL system components" inflation (H4).** ENIs + EBS volumes + snapshots counted as discrete components. **Fix:** document in Cover caveats and add a "primary components" count excluding derived attachments.

### Wasteful / risky calls
- **IAM per-principal fan-out** → replace with one paginated **`GetAccountAuthorizationDetails`** (users/groups/roles/policies + inline docs) + credential report for key/MFA age. Drop per-key `GetAccessKeyLastUsed` (report already has it).
- **`GenerateCredentialReport` polling** — call `GetCredentialReport` first; only generate on `ReportNotPresent`.
- **KMS `DescribeKey` on every AWS-managed key** — filter to CUSTOMER-managed before per-key describe.

---

## B. NEW COLUMNS — promote testable facts (the core upgrade)

Proposed additions (Stage 1 keeps all 43; these extend the contract; Stages 2/3 keep additive-only rule). Highest QSA value first.

| Key | Type | Source | PCI |
|-----|------|--------|-----|
| `imdsv2_required` | tri-bool | `DescribeInstances.MetadataOptions.HttpTokens` | 2.2.x |
| `metadata_hop_limit` | int | `MetadataOptions.HttpPutResponseHopLimit` | 2.2.x |
| `mfa_enabled` | tri-bool | credential report / `ListMFADevices` / Cognito | 8.4, 8.5 |
| `mfa_type` | str | `ListMFADevices`/`ListVirtualMFADevices` | 8.4.2 |
| `access_key_age_days` | int | credential report `access_key_*_last_rotated` | 8.3.9, 8.6.3 |
| `last_used_age_days` | int | `GetAccessKeyLastUsed` / `RoleLastUsed` / report | 8.2.6 |
| `is_root_account` / `root_usage` | tri-bool/str | credential report `<root_account>` | 8.2.2, 2.2.2 |
| `password_policy_summary` | str | `GetAccountPasswordPolicy` | 8.3.6/7/9 |
| `tls_min_version` | str | parsed from LB SslPolicy / CF / API GW / RDS | 4.2.1, 2.2.7 |
| `cert_expiry_date` | datetime | `acm:DescribeCertificate.NotAfter` | 4.2.1.1 |
| `cert_key_algo` | str | `acm:DescribeCertificate.KeyAlgorithm` | 4.2.1, 3.6 |
| `public_access_block` | tri-bool | account+bucket S3 PAB (all 4 on) | 1.3, 1.4, 7.2 |
| `publicly_shared` | tri-bool | snapshot/AMI share, RDS public, RAM | 1.3, 3.x, 7.2 |
| `kms_rotation_enabled` | tri-bool | `GetKeyRotationStatus.KeyRotationEnabled` | 3.6.1, 3.7.4 |
| `kms_rotation_period_days` | int | `GetKeyRotationStatus.RotationPeriodInDays` | 3.6.1.2 |
| `key_origin_manager` | str | `DescribeKey.KeyManager`,`Origin` | 3.6, 3.7 |
| `log_retention_days` | int | `DescribeLogGroups.retentionInDays` (split from backup) | 10.5.1 |
| `vuln_scan_status` | str | `inspector2:ListCoverage` | 11.3.1, 6.3.3 |
| `vuln_findings_summary` | str | `inspector2:ListFindings` (severity counts) | 11.3.1 |
| `patch_compliance` | str | `ssm:DescribeInstancePatchStates` (best-effort) | 6.3.3 |
| `anti_malware_status` | str | GuardDuty Malware Protection / else `NOT_COLLECTABLE` | 5.2, 5.3 |
| `change_detection_monitored` | tri-bool | Config recorder coverage | 11.5.2, 10.7 |
| `time_sync_source` | str | `NOT_COLLECTABLE` (in-guest) | 10.6 |
| `eol_status` | str | derived (runtime/engine/OS version) | 12.3.4, 6.3.3 |
| `deletion_protection` | tri-bool | RDS/ELB/EC2 termination protection | 10.5.1 |
| `auto_minor_version_upgrade` | tri-bool | `rds.AutoMinorVersionUpgrade` | 6.3.3 |
| `segmentation_role` | str | derived from resource_type (NSC objects) | 1.2, 11.4.5 |
| `iam_db_auth` | tri-bool | `rds.IAMDatabaseAuthenticationEnabled` | 8.x |

**New sentinel:** add `NOT_COLLECTABLE` (control exists but is not observable from read-only AWS APIs — in-guest/process/physical) distinct from `NOT_COLLECTED` (could have been gathered this run but wasn't). This is essential so the QSA never reads a blind spot as a control gap.

**Renames/splits:**
- Split `backup_retention` → `backup_config` + numeric `log_retention_days`.
- Promote out of `encryption_in_transit_detail`: `tls_min_version`, `cert_expiry_date`, `cert_key_algo`.
- Promote out of `encryption_at_rest_detail`: `kms_rotation_enabled`, `key_origin_manager`.
- Keep the free-text `*_detail` columns as the human narrative alongside the typed columns.

---

## C. UNDER-DETAILED EXISTING COLLECTORS — add these calls/fields

(Selected high/medium priority; full list in the API-coverage audit.)

- **EC2:** `MetadataOptions` (IMDSv2); account `GetEbsEncryptionByDefault`; `Monitoring.State`.
- **Security groups:** `DescribeSecurityGroupRules` (per-rule IDs); capture `PrefixListIds`.
- **Flow logs:** `TrafficType`, `LogDestinationType/Destination`, `DeliverLogsStatus`, `LogFormat`.
- **RDS:** `DeletionProtection`, `AutoMinorVersionUpgrade`, `IAMDatabaseAuthenticationEnabled`, `MultiAZ`, `CACertificateIdentifier`, `EnabledCloudwatchLogsExports`, PerformanceInsights; parameter-group `rds.force_ssl`/`require_secure_transport`; `DescribeDBSnapshots` + public attribute; serverless detection (`EngineMode`).
- **ElastiCache:** `DescribeReplicationGroups` (AtRest/Transit/AuthToken).
- **S3:** account `s3control:GetPublicAccessBlock`; `GetBucketAcl` grants; `GetObjectLockConfiguration`; `GetBucketReplication`; `GetBucketLifecycleConfiguration`.
- **ELBv2:** `DescribeLoadBalancerAttributes` (access logs, drop-invalid-header, desync, deletion-protection); `DescribeSslPolicies`; `DescribeTargetGroups`; `DescribeListenerCertificates`.
- **CloudFront:** `GetDistributionConfig` (ViewerProtocolPolicy, WebACLId, Logging, origin protocol).
- **API Gateway:** `GetStages` (access logging, client cert, WAF assoc, method settings), custom-domain min TLS.
- **WAFv2:** `GetWebACL` (rules + DefaultAction), `GetLoggingConfiguration`, `ListResourcesForWebACL`.
- **CloudTrail:** `GetEventSelectors`, `GetInsightSelectors`, `IsOrganizationTrail`, `includeShadowTrails=True`.
- **CloudWatch Logs:** `DescribeMetricFilters` (10.4 events).
- **Config:** `DescribeConformancePacks`, `DescribeComplianceByConfigRule`, `DescribeDeliveryChannels`, recording-group scope.
- **KMS:** `RotationPeriodInDays`, `Origin`, `MultiRegion`; skip per-key describe on AWS-managed.
- **ACM:** `KeyAlgorithm`, `RenewalEligibility`, `Type`, in-use.
- **IAM:** `GetAccountAuthorizationDetails`; `ListVirtualMFADevices`; `ListServerCertificates` (legacy TLS certs); full password-policy fields.
- **Access Analyzer / GuardDuty / Security Hub / Inspector / Macie:** add **findings** (severity counts) + coverage, not just enablement.
- **Organizations:** `ListRoots`/`ListOrganizationalUnitsForParent` (OU tree), `DescribePolicy` (SCP body) + `ListTargetsForPolicy`.
- **MQ / Step Functions:** `DescribeBroker` (public+encryption), `DescribeStateMachine` (logging/tracing/role).

---

## D. MISSING SERVICES — add collectors (priority)

**High (likely CHD stores / direct exposure / primary access path):**
- AWS Network Firewall; RDS Proxy (RequireTLS/IAM auth); OpenSearch/Elasticsearch; Redshift Serverless; SSM Patch/Compliance + SSM Inventory; ECR image-scan findings; **IAM Identity Center / Identity Store** (primary human access).
- Resource Access Manager (RAM) shares (cross-account scope boundary).

**Medium:** Firewall Manager, Athena, Glue, EMR, SageMaker, CodeBuild/CodePipeline, App Runner, DMS, ACM PCA.
**Low:** WorkSpaces, AppStream, AppMesh, Route53 Resolver, MSK, MWAA, Trusted Advisor/Health, Audit Manager.
**Also missing as collectors but in matrix:** `account:ListRegions` (currently inline in regions.py — fine), Route 53 record sets + query logging + DNSSEC, EFS mount targets/policy, AWS Backup plans/vault-lock.

---

## E. Proposed sheet/output changes

- New workbook tabs: **Identity & Access** (IAM/MFA/keys focus), **Encryption** (at-rest + in-transit + KMS), **Logging & Monitoring** (CloudTrail/Config/retention), **Vulnerability & Patch** (Inspector/SSM/ECR), and a **PCI Requirement Coverage** matrix sheet (requirement → which columns/collectors evidence it, with Covered/Partial/Not-collectable).
- Cover sheet: add the `GenerateCredentialReport` read-only note, the NOT_COLLECTABLE legend, and the "primary vs total components" counts.
- Data Dictionary: add the new columns + the `NOT_COLLECTABLE` sentinel.

---

## Recommended execution order

**Phase R1 — correctness (no schema change):** fix truncation, region-probe fail-open, throttle-gate on `call`, policy-parse, snapshot/AMI sharing, S3 access-denied handling, RDS cluster dead code, mgmt-account inclusion, IAM `GetAccountAuthorizationDetails`. *These make the current inventory trustworthy.*

**Phase R2 — schema promotion:** add `NOT_COLLECTABLE`; add the new typed columns; split/rename; update model, render, workbook, Data Dictionary, JSON schema (bump `schema_version` 1.0.0 → 1.1.0, additive).

**Phase R3 — detail enrichment:** add the missing API calls/fields to existing collectors (Section C).

**Phase R4 — new collectors:** High-priority services first (Section D), then Medium/Low.

**Phase R5 — output:** new domain tabs + PCI Requirement Coverage sheet; verify formatting; re-run offline tests + add tests for new columns/sentinels.

---

## Open questions for you (before building)

1. **Scope of this pass** — do all of R1–R5, or land R1+R2 (trustworthy + QSA-pivotable) first and treat R3–R5 (breadth of services/fields) as a follow-on? R1+R2 is the high-leverage core; R4 (new services) is the long tail.
2. **New-service breadth** — add all High-priority new collectors now, or only those you actually run (e.g., do you use OpenSearch / Redshift Serverless / Network Firewall / RDS Proxy / Identity Center)? Tailoring avoids dead collectors.
3. **IAM rewrite** — switch the IAM collector to `GetAccountAuthorizationDetails` (big throttle win, moderate rewrite) now, or defer? It changes the IAM record shape that Stage 2 consumes.
4. **In-guest signals (SSM patch/inventory, IMDSv2 hop)** — include best-effort SSM patch/compliance + SSM Inventory now (valuable for Req 6/2 but only covers SSM-managed instances), or hold?
5. **`schema_version` bump** — confirm OK to go 1.0.0 → 1.1.0 (additive) so Stage 2/3 see the richer record.
