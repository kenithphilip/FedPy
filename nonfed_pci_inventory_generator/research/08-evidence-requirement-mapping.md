# 08 — PCI DSS v4.0.1 Evidence ↔ Requirement Mapping (Stage 3 research)

> **Purpose.** Map ALL 12 PCI DSS v4.0.1 requirements (and key sub-requirements) to the specific
> AWS configuration data point(s) that evidence them, the API call that retrieves each, and —
> critically for this stage — **whether the data point is already collected at inventory time
> (Stage 1/2) or needs a targeted follow-up query in Stage 3.**
>
> **Filename note.** The prompt asked for `research/06-evidence-requirement-mapping.md`, but `06`
> is the Stage 2 scope research and `04` is the Stage 1 re-audit evidence mapping. This is `08` to
> avoid clobbering. It supersedes/extends `04` by adding the *collected-vs-follow-up* dimension and
> the inventory-driven enrichment plan.
>
> **Sources:** PCI DSS v4.0.1 + testing procedures, PCI SSC Glossary, AWS service docs, boto3.
> Standard text is paraphrased — no large copyrighted passages. `[ASSUMPTION]` flags anything not
> verifiable from an authoritative source here.

---

## 0. The central design fact (please confirm the framing)

The Stage 1 inventory already carries **71 typed columns** of per-resource configuration evidence
(IMDSv2, encryption-at-rest/in-transit, TLS min version, cert expiry, KMS rotation, MFA, key age,
log retention, patch/vuln status, public exposure, etc. — see `research/02`), and Stage 2 added
scope category + confidence per resource. **Most config evidence a QSA wants is therefore already
present in the artifact.** Re-fetching it would be wasteful and would violate the prompt's "augment,
never re-collect" intent.

So Stage 3's real work is three-fold:

1. **MAP** — re-present the evidence already in the inventory, organized **by PCI requirement
   domain**, each row traceable to its resource ARN and carrying scope category + confidence. This
   is pure read-from-artifact; no new API calls.
2. **FOLLOW-UP QUERY** — run the *small set* of genuinely-missing, inventory-driven queries
   (Section 2): primarily **security-service findings** attached to resources, plus a few
   per-resource details Stage 1 only summarized. This is the "query for the specific items
   identified during inventory" step.
3. **DERIVE** — compute account/scope-level **indicators** (Section 3), clearly labelled "tool
   indicators to assist assessment — NOT a compliance determination."

> **Honest framing:** the bulk of Stage 3 value is (1) + (3). The follow-up queries (2) are
> deliberately bounded — we do NOT re-walk every resource type; we query only what the inventory
> says exists and what isn't already captured. This keeps the run read-only, fast, and
> rate-limit-safe (reusing Stage 1 infra).

---

## 1. Requirement → evidence → API → source (the master mapping)

Legend for **Source**: `INV` = already in the inventory artifact (no new call); `FOLLOW-UP` = a
targeted Stage 3 query; `DERIVED` = computed indicator; `N/A-RO` = not observable read-only
(in-guest/process/physical) — recorded as `NOT_COLLECTABLE`; `SHARED` = AWS shared-responsibility.

### Requirement 1 — Network Security Controls
| Sub-req | Evidence data point | API | Source |
|---------|--------------------|-----|--------|
| 1.2/1.3 | SG ingress/egress rulesets; `0.0.0.0/0` to sensitive ports | `ec2:DescribeSecurityGroups` (+ Stage2 `DescribeSecurityGroupRules`) | INV (`relationships.ingress_rules/egress_rules`, `exposure_basis`) |
| 1.3 | NACL rules, deny-by-default | `ec2:DescribeNetworkAcls` | INV (note) + Stage2 gap-fetch |
| 1.3.1/1.3.2 | Internet ingress/egress paths (IGW/NAT/routes) | `ec2:DescribeRouteTables` | INV (`relationships.route_targets`) + Stage2 |
| 1.2.5 | Segmentation controls inventory | derived | INV (`segmentation_role`) + Stage2 reachability paths |
| 1.4 | VPC flow logs on + traffic type ALL | `ec2:DescribeFlowLogs` | INV (`logging_enabled`/`logging_detail` on VPC) |
| 1.x | NSC business justification / 6-monthly review | — | N/A-RO (process) |

### Requirement 2 — Secure Configuration
| 2.2.1/2.2.6 | IMDSv2 enforced, hop limit | `ec2:DescribeInstances.MetadataOptions` | INV (`imdsv2_required`, `metadata_hop_limit`) |
| 2.2.x | Default VPC in use; default SG with rules | `ec2:DescribeVpcs`/`DescribeSecurityGroups` | INV (notes / `segmentation_role`) |
| 2.2.2 | Vendor-default creds (root usage, default RDS user) | credential report; `rds:DescribeDBInstances.MasterUsername` | INV (`is_root_account`, IAM data) |
| 2.2.7 | Non-console admin encrypted (no open 22/3389) | derived from SG + SSM | INV (`exposure_basis`) |
| 2.2 | Config-rule / conformance-pack compliance per resource | `config:GetComplianceDetailsByResource` | **FOLLOW-UP** |
| 2.2 | In-guest hardening / changed local passwords | — | N/A-RO |

### Requirement 3 — Protect Stored Data
| 3.5/3.6 | Encryption at rest (EBS/RDS/S3/DynamoDB/EFS/…) | per-service | INV (`encryption_at_rest`, `_detail`) |
| 3.6.1/3.7.4 | KMS rotation enabled + period; key origin/manager | `kms:GetKeyRotationStatus`, `DescribeKey` | INV (`kms_rotation_enabled`, `kms_rotation_period_days`, `key_origin_manager`) |
| 3.6 | KMS key policy principals (who can decrypt CDE) | `kms:GetKeyPolicy` | INV (`iam_policy_data.key_policy`) + Stage2 IAM graph |
| 3.x | Public snapshot/AMI exposure of stored data | `ec2:DescribeSnapshotAttribute`/`DescribeImageAttribute` | INV (`publicly_shared`) |
| 3.2/3.x | Macie sensitive-data findings (PAN in S3) | `macie2:GetFindingsStatistics`/`DescribeBuckets` | **FOLLOW-UP** (best-effort) |
| 3.x | Whether PAN actually stored / minimized / SAD purged | — | N/A-RO (data content) |

### Requirement 4 — Strong Crypto in Transit
| 4.2.1 | TLS min version on LB/CloudFront/API GW | `elbv2:DescribeListeners`/`DescribeSslPolicies`, `cloudfront`, `apigateway` | INV (`encryption_in_transit`, `tls_min_version`, `_detail`) |
| 4.2.1.1 | ACM cert validity/expiry/algorithm | `acm:DescribeCertificate` | INV (`cert_expiry_date`, `cert_key_algo`) |
| 4.2.1 | RDS force-SSL; Redshift require_ssl | param groups | INV (`encryption_in_transit` on db) |
| 4.2.1 | Weak SSL policy / prohibited ciphers list | `elbv2:DescribeSslPolicies` (cipher detail) | **FOLLOW-UP** (resolve named policy → ciphers, only for in-scope LBs) |

### Requirement 5 — Anti-Malware
| 5.2/5.3 | Anti-malware presence/health | — | N/A-RO (in-guest); INV records `anti_malware_status=NOT_COLLECTABLE` |
| 5.x | GuardDuty Malware Protection enablement + findings | `guardduty:GetDetector`, `ListFindings` (malware types) | INV (enablement) + **FOLLOW-UP** (malware finding count) |

### Requirement 6 — Secure Systems & Software
| 6.3.1/11.3 | Inspector vuln findings per resource | `inspector2:ListFindings`/`ListFindingAggregations` | INV (account summary) + **FOLLOW-UP** (per-resource aggregation) |
| 6.3.2 | Bespoke software inventory + versions | per-service | INV (`software_app`, `software_version`, `is_bespoke_software`) |
| 6.3.3 | Patch compliance (SSM Patch Manager) | `ssm:DescribeInstancePatchStates` | INV (`patch_compliance`) |
| 6.3.3/12.3.4 | EOL / unsupported runtimes | derived | INV (`eol_status`) |
| 6.4.2 | WAF on public web apps | `wafv2:GetWebACL`, association | INV (WAF records) + **FOLLOW-UP** (web-ACL→resource association for in-scope public apps) |
| 6.x | ECR image scan findings | `ecr:DescribeImageScanFindings` | INV (`vuln_scan_status` scan-on-push) + **FOLLOW-UP** (latest scan finding counts) |

### Requirement 7 — Least Privilege
| 7.2 | Overly-permissive IAM (wildcards, admin) | `iam:GetAccountAuthorizationDetails` | INV (`iam_policy_data`) + Stage2 IAM graph |
| 7.2.x | Access Analyzer external/public-access findings | `accessanalyzer:ListFindings` | INV (analyzer summary) + **FOLLOW-UP** (active findings detail) |
| 7.x | Permission boundaries / SCP guardrails | IAM/Org data | INV (`iam_policy_data`) |
| 7.x | Business-need justification / access reviews | — | N/A-RO (process) |

### Requirement 8 — Identify & Authenticate
| 8.3/8.4/8.5 | MFA coverage, password policy | credential report, `iam:GetAccountPasswordPolicy` | INV (`mfa_enabled`, `mfa_type`, `password_policy_summary`) |
| 8.3.9/8.6.3 | Access-key age/rotation | credential report | INV (`access_key_age_days`) |
| 8.2.6 | Inactive credentials | credential report / `RoleLastUsed` | INV (`last_used_age_days`) |
| 8.2.2/8.6.1 | Root usage / root keys | credential report | INV (`is_root_account`, IAM account-settings) |
| 8.x | DB IAM auth | `rds` | INV (`iam_db_auth`) |

### Requirement 9 — Physical
| 9.x | AWS data-centre physical security | — | SHARED (AWS Artifact AOC/SOC2) — noted, not collected |
| 9.5.x | POI devices | — | N/A-RO (out of cloud scope) |

### Requirement 10 — Logging & Monitoring
| 10.2/10.3 | CloudTrail enabled, multi-region, validation, KMS, event selectors | `cloudtrail:*` | INV (trail records, `logging_detail`) |
| 10.5.1 | Log retention ≥ 365d (12 months) | `logs:DescribeLogGroups.retentionInDays` | INV (`log_retention_days`) + DERIVED (compliance flag) |
| 10.7 | Config recording (change detection) | `config:DescribeConfigurationRecorders` | INV (`change_detection_monitored`, config records) |
| 10.4 | Metric filters/alarms for key events | `logs:DescribeMetricFilters`, `cloudwatch:DescribeAlarms` | INV (alarm records) + **FOLLOW-UP** (10.4-event metric-filter coverage check) |
| 10.6 | Time sync (NTP) | — | N/A-RO (in-guest); INV `time_sync_source=NOT_COLLECTABLE` |
| 10.x | Log immutability (S3 object-lock, MFA-delete on trail bucket) | `s3:GetObjectLockConfiguration` | INV (`backup_config` on S3) |

### Requirement 11 — Test Security
| 11.3.1 | Vuln scanning (Inspector) enablement + findings | `inspector2:*` | INV + **FOLLOW-UP** |
| 11.3 | External scan targets (public IPs/endpoints) | derived | INV (`public_exposed`, `public_ips`, `dns_names`) + DERIVED (target list) |
| 11.5 | Change detection (Config rules + history) | `config:*` | INV + **FOLLOW-UP** (rule compliance) |
| 11.5.1 | GuardDuty (IDS) enablement + findings | `guardduty:*` | INV + **FOLLOW-UP** |
| 11.4.x | Pen test / segmentation test; ASV external scans | — | N/A-RO (out-of-band); Stage 2 provides segmentation config evidence |
| 11.2 | Rogue wireless | — | N/A-RO (physical/RF) |

### Requirement 12 — Program & Scope
| 12.5.1 | System-component inventory (complete + current) | the artifact itself | INV (the whole inventory) + DERIVED (completeness stats) |
| 12.5.2 | Scope confirmation data (data flows, connections, segmentation) | Stage 2 | INV (`pci_scope`, scope_analysis) |
| 12.x | Policies, risk assessment, training, IR plan, TPSP mgmt | — | N/A-RO (documentation) |
| 12.x | Security Hub posture (CIS/PCI standard) compliance | `securityhub:GetEnabledStandards`, `DescribeStandardsControls`, `GetFindings` | INV (hub record) + **FOLLOW-UP** (control compliance counts) |

---

## 2. Stage 3 follow-up queries (the genuinely-new, inventory-driven calls)

Run ONLY these, and only where the inventory indicates the service exists / a resource is in scope.
All read-only, routed through Stage 1's `CallContext` (rate-limited + error-captured), parallel via
`run_work_units`, per (account, region).

| # | Query | boto3 | Attaches to | Drives |
|---|-------|-------|-------------|--------|
| F1 | **Security Hub findings** by severity + standard control status | `securityhub:GetFindings`, `DescribeStandardsControls`, `GetEnabledStandards` | account/region + resource ARN in finding | Req 11/12 posture |
| F2 | **GuardDuty findings** by severity (+ malware-protection types) | `guardduty:ListFindings`+`GetFindings` (or `GetFindingsStatistics`) | detector → resource ARNs in findings | Req 5/11 |
| F3 | **Inspector findings** aggregated by resource | `inspector2:ListFindingAggregations` (AWS_EC2_INSTANCE / AWS_ECR_IMAGE / AWS_LAMBDA_FUNCTION) | resource ARN | Req 6/11 |
| F4 | **Access Analyzer active findings** | `accessanalyzer:ListFindings` (status=ACTIVE) | resource ARN in finding | Req 7 |
| F5 | **Config compliance** per resource / rule | `config:GetComplianceDetailsByConfigRule` or `DescribeComplianceByResource` | resource ARN | Req 2/11.5 |
| F6 | **Macie** sensitive-data finding stats (best-effort) | `macie2:GetFindingsStatistics` | S3 bucket ARN | Req 3 |
| F7 | **ELBv2 SSL policy cipher detail** for in-scope internet-facing LBs only | `elbv2:DescribeSslPolicies` | LB ARN | Req 4 (prohibited ciphers) |
| F8 | **WAF web-ACL → resource association** for in-scope public apps | `wafv2:ListResourcesForWebACL` / `GetWebACLForResource` | LB/CloudFront/API ARN | Req 6.4.2 |

> **Bounded by design.** F7/F8 run only for in-scope, internet-facing resources the inventory
> already flagged — not every LB. Findings (F1–F6) are fetched once per (account, region) and joined
> to resources by ARN. If a service is not enabled, the call returns empty / AccessDenied → recorded
> as `NOT_COLLECTED`/`ACCESS_DENIED`, never fatal.

**Finding→resource join:** AWS findings reference resources by ARN (Security Hub `Resources[].Id`,
GuardDuty `Resource`, Inspector `resources[].id`, Access Analyzer `resource`). We join on ARN; a
finding whose resource isn't in the inventory is still recorded (attached to account/region) with a
note, so nothing is lost.

---

## 3. Derived indicators (assist assessment — NOT compliance determinations)

Computed from the enriched artifact, each labelled loudly as a tool indicator. Computed
**overall** and **broken down by scope category** (CDE / connected-to / security-impacting), since
a QSA cares most about the in-scope subset.

| Indicator | Definition |
|-----------|------------|
| Encryption-at-rest coverage % | encrypted ÷ (applicable resources) — overall + per scope |
| Encryption-in-transit coverage % | TLS-enforced ÷ (applicable endpoints) |
| MFA coverage % | IAM principals (+ root) with MFA ÷ total |
| Public-exposure count | resources with `public_exposed=Yes` (+ list), per scope |
| Unencrypted-resource list | `encryption_at_rest=No`, per scope |
| Stale-credential list | access-key age > 90d or last-used > 90d |
| Certs/keys nearing expiry | ACM/IAM-server certs expiring < 30/90d; KMS rotation disabled |
| CloudTrail coverage | multi-region trail present + logging + validation + KMS |
| Config coverage | recorder recording in each in-use region |
| Log-retention compliance flag | log groups with retention < 365d (per 10.5.1) |
| Overly-permissive IAM flag count | wildcard `*:*` / admin attachments / `*` trust |
| IMDSv2 enforcement % | instances with `imdsv2_required=Yes` ÷ total instances |
| Patch non-compliance count | `patch_compliance=NON_COMPLIANT` |
| Vuln findings rollup | crit/high counts from Inspector/Security Hub/GuardDuty |

**Thresholds** (90d staleness, 30/90d cert expiry, 365d retention) are conventional and documented;
they are indicators, not pass/fail verdicts.

---

## 4. Output plan (final consolidated QSA workbook)

Extend the workbook (augment, never overwrite Stage 1/2 sheets) with:
- **Evidence by requirement** — one sheet per domain `Req 01 NSC` … `Req 12 Program`, each row =
  (resource ARN, name, region, scope category + confidence, the requirement-relevant evidence
  fields, attached findings). Resource-less requirements (9 physical, parts of 12) get a short
  shared-responsibility / process note row.
- **PCI Requirement Mapping** — every data point/column → the requirement(s) it supports (the whole
  tool, spanning Stages 1–3), with collected-vs-follow-up flag.
- **Findings & Indicators** — the Section 3 indicators, overall + per scope, plus the security-service
  findings rollup. Header banner: "Indicators assist assessment — NOT compliance determinations."
- **QSA Notes** — "how scope was determined" (seeds → reachability → IAM → segmentation), "known
  limitations / shared-responsibility caveats," and the read-only attestation.

Plus consolidated CSV + the final JSON artifact `output/inventory-evidence.json` (superset of
`inventory-scoped.json` + per-resource `evidence` block + `indicators` + `requirement_mapping`).

---

## 5. Assumptions to confirm before building

1. **Filename `08`** (06/04 taken). ✅ assumed.
2. **Inventory-as-substrate framing** (Section 0): Stage 3 mostly maps existing evidence + a bounded
   set of follow-up *findings* queries, rather than re-collecting per-resource config. Confirm.
3. **Follow-up scope:** F1–F8 as listed; bounded to in-scope/enabled. Confirm none missing / none unwanted.
4. **Findings join by ARN**, with orphan findings retained + noted.
5. **Indicator thresholds** (90d / 30-90d / 365d) are conventional defaults, configurable, labelled indicators.
6. **Fallback:** if only `inventory.json` exists (no Stage 2), run with a loud "scope context missing"
   banner; evidence rows carry `pci_scope=UNDETERMINED`.
7. **Stage 3 JSON name** `output/inventory-evidence.json`. Confirm.
