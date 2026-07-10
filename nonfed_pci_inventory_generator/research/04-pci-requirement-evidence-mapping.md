# 04 — PCI DSS v4.0.1 → Read-Only AWS Inventory Evidence Mapping

> **Purpose:** For each of the 12 PCI DSS v4.0.1 requirements, map what a QSA must
> assess to the AWS configuration signals a **read-only** inventory can (and
> cannot) surface, with the boto3 operation + response field for each collectable
> signal. This is the authority for which columns/collectors exist and — equally
> important — what the tool must explicitly mark `NOT_COLLECTABLE` so the
> inventory never *implies* a control is absent when it simply isn't observable
> from the control plane.
>
> Standard text is paraphrased. `[ASSUMPTION]` marks items not verified against an
> authoritative source. AWS config signals are **necessary but not sufficient** —
> a passing signal supports, but does not prove, a requirement; a failing signal
> is strong evidence of a gap.

---

## Cross-cutting summary (read first)

**Strongly collectable (control-plane config):**
- Req 1 — SG/NACL/route-table rules, flow logs, gateways, peering/TGW.
- Req 2 — IMDSv2, default-VPC use, public-access blocks, RDS defaults.
- Req 3 — encryption-at-rest enablement everywhere, KMS rotation/policy.
- Req 4 — TLS policy on LB/CloudFront/API GW/RDS endpoints, ACM cert validity.
- Req 6/11 — Inspector/ECR scan enablement & findings, SSM patch state, WAF.
- Req 7/8 — IAM wildcards/boundaries/SCPs, MFA, password policy, key age, credential report.
- Req 10 — CloudTrail multi-region+validation+KMS, Config, CloudWatch retention, access logs.
- Req 12 — inventory currency + tagging governance (supporting evidence).

**NOT collectable read-only (must come from other evidence — flag explicitly):**
- In-guest: OS hardening, anti-malware agents (Req 5), file-integrity/change-detection (11.5.2), local creds, running services, NTP/time-sync (10.6).
- Data content: whether PAN/SAD is stored/minimized/masked (Req 3 content), in-transit payloads (Req 4).
- Human/process: rule justifications & reviews (1), secure SDLC/change mgmt (6), access reviews/business-need (7), policy/training/risk-assessment/IR testing/TPSP mgmt (12), daily log review (10).
- Point-in-time/external: ASV external scans, penetration tests, segmentation tests (Req 11).
- Physical: AWS data centers via AWS Artifact attestation (Req 9); customer premises & POI devices out of AWS scope.
- Third-party IdP enforcement detail (Req 8 when federated).

---

## Requirement 1 — Network Security Controls

Intent: NSCs restrict traffic to/from the CDE; deny-by-default; restrict inbound from untrusted networks; rulesets justified and reviewed ≥ every 6 months.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| SG ingress/egress, detect `0.0.0.0/0`/`::/0` esp. to 22/3389/DB ports | Yes | `ec2:DescribeSecurityGroups` → `IpPermissions[].IpRanges[].CidrIp`, `FromPort/ToPort/IpProtocol`; `DescribeSecurityGroupRules` for rule IDs |
| NACL rules + ordering | Yes | `ec2:DescribeNetworkAcls` → `Entries[]` (`RuleNumber`,`RuleAction`,`CidrBlock`,`Egress`,`PortRange`) |
| Default SG has no rules (deny-by-default) | Yes | `ec2:DescribeSecurityGroups` (group-name=default) |
| Route tables → IGW/NAT/peering/TGW paths | Yes | `ec2:DescribeRouteTables` → `Routes[]` |
| IGW / egress-only IGW / NAT present | Yes | `ec2:DescribeInternetGateways`, `DescribeEgressOnlyInternetGateways`, `DescribeNatGateways` |
| Peering / TGW attachments (trust boundaries) | Yes | `ec2:DescribeVpcPeeringConnections`, `DescribeTransitGatewayAttachments` |
| VPC flow logs on + traffic type ALL + delivering | Yes | `ec2:DescribeFlowLogs` → `TrafficType`,`LogDestination`,`DeliverLogsStatus`,`LogFormat` |
| AWS Network Firewall policies/rule groups | Yes | `network-firewall:ListFirewalls`,`DescribeFirewall`,`DescribeFirewallPolicy`,`DescribeLoggingConfiguration` |
| Firewall Manager org policies | Yes | `fms:ListPolicies`,`GetPolicy`,`GetComplianceDetail` |
| WAF/Shield at edge | Yes | `wafv2:ListWebACLs`,`GetWebACL` |
| CDE membership / rule business-justification / 6-monthly review | **No** | scope is human-supplied (tags help); reviews are process |

---

## Requirement 2 — Secure Configuration

Intent: change/disable vendor defaults; harden per standards; only necessary services/ports; disable insecure services; change wireless defaults.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| IMDSv2 enforced (token required) | Yes | `ec2:DescribeInstances` → `MetadataOptions.HttpTokens=="required"`, `HttpEndpoint`, `HttpPutResponseHopLimit` |
| Default VPC in use | Yes | `ec2:DescribeVpcs` → `IsDefault`; cross-ref instance `VpcId` |
| Default SG with rules | Yes | `ec2:DescribeSecurityGroups` |
| RDS default master user / public | Yes | `rds:DescribeDBInstances` → `MasterUsername`,`PubliclyAccessible` |
| S3 not public (account + bucket) | Yes | `s3control:GetPublicAccessBlock`, `s3:GetPublicAccessBlock`, `GetBucketPolicyStatus.IsPublic`, `GetBucketAcl` |
| Config conformance pack / CIS compliance | Yes | `config:DescribeConformancePacks`, `DescribeComplianceByConfigRule` |
| SSM Inventory of installed apps (partial in-guest) | Partial | `ssm:GetInventory`/`ListInventoryEntries` (`AWS:Application`) |
| OS hardening, changed local passwords, disabled in-guest services | **No** | in-guest |
| Wireless defaults | **No** | physical/network gear |

---

## Requirement 3 — Protect Stored Account Data

Intent: minimize storage; render PAN unreadable (strong crypto/truncation/tokenization/hashing); don't retain SAD; protect & manage keys.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| EBS encrypted + account default | Yes | `ec2:DescribeVolumes`→`Encrypted`,`KmsKeyId`; `ec2:GetEbsEncryptionByDefault` |
| RDS / Aurora at rest | Yes | `rds:DescribeDBInstances`/`DescribeDBClusters`→`StorageEncrypted`,`KmsKeyId` |
| S3 default SSE (KMS pref) | Yes | `s3:GetBucketEncryption`→`Rules[].ApplyServerSideEncryptionByDefault` |
| DynamoDB / EFS / Redshift / ElastiCache / OpenSearch / SQS / SNS at rest | Yes | resp. `DescribeTable.SSEDescription`; `efs:DescribeFileSystems.Encrypted`; `redshift…Encrypted`; `elasticache:DescribeReplicationGroups.AtRestEncryptionEnabled`; `opensearch…EncryptionAtRestOptions`; queue/topic `KmsMasterKeyId` |
| KMS rotation + period + origin/manager | Yes | `kms:GetKeyRotationStatus`→`KeyRotationEnabled`,`RotationPeriodInDays`; `DescribeKey`→`KeyManager`,`Origin`,`MultiRegion` |
| KMS key policies (access restriction) | Yes | `kms:GetKeyPolicy` |
| Secrets in Secrets Manager + rotation | Yes | `secretsmanager:ListSecrets`→`RotationEnabled`,`KmsKeyId` |
| Plaintext secrets in SSM (should be SecureString) | Partial | `ssm:DescribeParameters`→`Type` (flag `String`); never read values |
| Plaintext creds in EC2 UserData / launch templates | Yes (detectable) | `ec2:DescribeInstanceAttribute(userData)`, `DescribeLaunchTemplateVersions.LaunchTemplateData.UserData` |
| Public snapshot/AMI (CHD-at-rest leak) | Yes | `ec2:DescribeSnapshotAttribute(createVolumePermission)`, `DescribeImageAttribute(launchPermission)`, `rds:DescribeDBSnapshotAttributes(restore=all)` |
| Whether PAN exists / minimized / SAD purged | **No** (Macie partial for S3) | `macie2:GetFindings` |
| Key ceremonies, split knowledge, dual control | **No** | process |

---

## Requirement 4 — Strong Crypto in Transit

Intent: protect PAN over open/public networks with strong crypto & secure protocols; trusted keys/certs only; no weak versions/ciphers.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| ALB/NLB TLS listener + modern policy (≥TLS1.2) | Yes | `elbv2:DescribeListeners`→`Protocol`,`SslPolicy`; `DescribeSslPolicies` for ciphers |
| Classic ELB listener policies | Yes | `elb:DescribeLoadBalancers.ListenerDescriptions`, `DescribeLoadBalancerPolicies` |
| CloudFront min TLS + viewer protocol | Yes | `cloudfront:GetDistributionConfig`→`ViewerCertificate.MinimumProtocolVersion`,`DefaultCacheBehavior.ViewerProtocolPolicy` |
| API Gateway custom-domain min TLS | Yes | `apigateway:GetDomainNames.securityPolicy`; `apigatewayv2:GetDomainNames` |
| ACM cert validity/expiry/algo/issuer/in-use | Yes | `acm:DescribeCertificate`→`NotAfter`,`Status`,`KeyAlgorithm`,`Issuer`,`InUseBy` |
| RDS force SSL | Yes | `rds:DescribeDBParameters` → `rds.force_ssl`/`require_secure_transport` |
| Redshift require_ssl | Yes | `redshift:DescribeClusterParameters` → `require_ssl` |
| S3 bucket policy denies non-TLS | Yes | `s3:GetBucketPolicy` → `aws:SecureTransport=false` Deny |
| OpenSearch node-to-node + HTTPS enforce | Yes | `opensearch:DescribeDomain`→`NodeToNodeEncryptionOptions`,`DomainEndpointOptions.EnforceHTTPS`,`TLSSecurityPolicy` |
| Actual negotiated protocol end-to-end / PAN over unprotected messaging | **No** | runtime / process |

---

## Requirement 5 — Anti-Malware  *(predominantly NOT collectable read-only)*

Intent: anti-malware on commonly-affected systems; current; periodic + active scans; audit logs; tamper-resistant; anti-phishing (5.4).

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| GuardDuty enabled + Malware Protection feature | Partial | `guardduty:ListDetectors`,`GetDetector.Status`, detector features; `ListMalwareProtectionPlans` |
| GuardDuty malware findings (EC2/EBS/S3) | Partial | `guardduty:ListFindings`,`GetFindings` |
| SSM Inventory shows AV installed (weak proxy) | Partial | `ssm:GetInventory` (`AWS:Application`) |
| In-guest AV present/current/scanning/logging/tamper-proof | **No** | in-guest agent — the core of Req 5 |

**Honest limit:** Req 5 is mostly in-guest. The tool reports GuardDuty/Malware-Protection enablement and marks `anti_malware_status = NOT_COLLECTABLE` for hosts.

---

## Requirement 6 — Secure Systems & Software

Intent: secure dev of bespoke/custom software; identify & risk-rank vulns; patch within defined timeframes; change management; dev/test/prod separation; protect public web apps (e.g., WAF).

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| ECR image scanning + findings | Yes | `ecr:GetRegistryScanningConfiguration`, `DescribeImageScanFindings` |
| Inspector enabled + findings (EC2/ECR/Lambda) | Yes | `inspector2:BatchGetAccountStatus`, `ListFindings`,`ListCoverage` |
| SSM patch state / compliance | Yes | `ssm:DescribeInstancePatchStates`, `ListComplianceSummaries`, `ListResourceComplianceSummaries` |
| WAF associated to public ALB/CF/API GW (6.4.2) | Yes | `wafv2:ListResourcesForWebACL`,`GetWebACLForResource`,`GetWebACL` |
| Public-facing app inventory (what needs WAF) | Yes | `elbv2…Scheme=internet-facing`, `cloudfront:ListDistributions`, `apigateway:GetRestApis` |
| Lambda deprecated/unsupported runtimes | Yes | `lambda:ListFunctions.Runtime` |
| Env separation via accounts/tags | Partial | `organizations:ListAccounts`, tags |
| CI/CD presence | Partial | `codepipeline:ListPipelines`, `codebuild:BatchGetProjects` (`Environment.PrivilegedMode`,`VpcConfig`) |
| Bespoke SW inventory / SBOM | Partial | `inspector2:CreateSbomExport` (async→S3) |
| Secure SDLC, code review, change approval | **No** | process |

---

## Requirement 7 — Least Privilege / Need-to-Know

Intent: limit access to least privilege by job need; RBAC; default-deny; explicit assignment/approval; reviews.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| IAM wildcards (`Action/Resource "*"`) managed + inline | Yes | `iam:GetAccountAuthorizationDetails` (bulk), or `GetPolicyVersion`/`GetRolePolicy`/`GetUserPolicy` |
| Admin / overly-broad attachments | Yes | `iam:ListAttached*Policies` |
| Permission boundaries | Yes | `iam:GetRole`/`GetUser`→`PermissionsBoundary` |
| SCP guardrails + targets | Yes | `organizations:ListPolicies`,`DescribePolicy`,`ListTargetsForPolicy` |
| Role trust policies | Yes | `iam:GetRole.AssumeRolePolicyDocument` |
| Unused access (least-privilege signal) | Yes | `iam:GetRole.RoleLastUsed`; `get_service_last_accessed_details` (heavy) |
| Access Analyzer external/public findings | Yes | `accessanalyzer:ListFindings`→`isPublic`,`status` |
| Public resource policies (S3/KMS/SNS/SQS) | Yes | resp. `GetBucketPolicy`/`GetKeyPolicy`/topic/queue `Policy` |
| Business-need justification / reviews performed | **No** | process |

---

## Requirement 8 — Identify & Authenticate

Intent: unique IDs; restrict shared/generic; strong auth (password + MFA); MFA for all CDE access + remote/admin/console; protect & lifecycle-manage factors.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| Password policy (length/complexity/reuse/expiry) | Yes | `iam:GetAccountPasswordPolicy` → all fields |
| Root MFA | Yes | `iam:GetAccountSummary.AccountMFAEnabled` |
| Per-user MFA + virtual/hardware | Yes | `iam:ListMFADevices`,`ListVirtualMFADevices`; credential report |
| Credential report (MFA, pw-enabled, last-used, key age/rotation, inactivity) | Yes | `iam:GenerateCredentialReport`+`GetCredentialReport` (CSV) |
| Access key age + last used | Yes | `iam:ListAccessKeys.CreateDate`, `GetAccessKeyLastUsed.LastUsedDate` |
| Root access keys exist (should not) | Yes | `iam:GetAccountSummary.AccountAccessKeysPresent` |
| Inactive users / stale creds | Yes | credential report |
| IAM Identity Center (SSO) usage + MFA | Partial | `sso-admin:ListInstances`,`ListPermissionSets`; `identitystore:ListUsers` `[ASSUMPTION]` device-level MFA limited via API |
| Cognito user-pool MFA/password policy | Yes | `cognito-idp:DescribeUserPool`,`GetUserPoolMfaConfig` |
| Shared/generic accounts (heuristic only) | Partial | `iam:ListUsers` naming |
| Federated IdP enforcement / in-app auth | **No** | third-party / in-app |

---

## Requirement 9 — Physical  *(AWS shared responsibility / out of scope)*

Intent: control physical access to systems/media/facilities; visitor mgmt; media handling/destruction; protect POI devices.

| Signal | Collectable | Source |
|--------|-------------|--------|
| AWS data-center physical security | **No — AWS responsibility** | AWS PCI DSS AOC / SOC2 / ISO via **AWS Artifact** |
| Customer offices / retail / POI devices | **No** | on-site assessment |

**Honest limit:** For AWS-hosted scope, Req 9 is evidenced by AWS's attestation via Artifact, not by a customer inventory. POI/physical premises are out of read-only AWS scope. The Cover sheet states this.

---

## Requirement 10 — Logging & Monitoring

Intent: capture access & key events; protect logs (tamper-evident); time-sync; review (incl. automated); retain ≥12 months (3 readily available); detect logging failures.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| CloudTrail enabled, multi-region, mgmt+data events | Yes | `cloudtrail:DescribeTrails`→`IsMultiRegionTrail`,`IncludeGlobalServiceEvents`,`KmsKeyId`; `GetTrailStatus.IsLogging`; `GetEventSelectors` (data events, R/W); `GetInsightSelectors` |
| Log-file validation (integrity) | Yes | `cloudtrail:DescribeTrails.LogFileValidationEnabled` |
| Trail log bucket not public + versioning + MFA-delete + object-lock | Yes | `s3:GetBucketPolicy`,`GetPublicAccessBlock`,`GetBucketVersioning.MFADelete`,`GetObjectLockConfiguration` |
| AWS Config recording (supports 10 & 11.5) | Yes | `config:DescribeConfigurationRecorders.recordingGroup.allSupported`, `…RecorderStatus.recording`, `DescribeDeliveryChannels` |
| CloudWatch Logs retention ≥365d | Yes | `logs:DescribeLogGroups.retentionInDays` |
| Org/central trail aggregation | Partial | `cloudtrail:DescribeTrails.IsOrganizationTrail` |
| ELB/CloudFront/S3/WAF access logging | Yes | `elbv2:DescribeLoadBalancerAttributes` (`access_logs.s3.enabled`); `cloudfront…Logging.Enabled`; `s3:GetBucketLogging`; `wafv2:GetLoggingConfiguration` |
| Metric filters/alarms for 10.4 events (root use, unauthorized API, policy change) | Yes | `logs:DescribeMetricFilters`, `cloudwatch:DescribeAlarms` |
| Logging-failure alerting (10.7) | Partial | `cloudwatch:DescribeAlarms`, `events:ListRules` |
| Time-sync / NTP (10.6) | **No (mostly)** | in-guest; Amazon Time Sync implicit `[ASSUMPTION]` → `time_sync_source = NOT_COLLECTABLE` |
| Daily/automated log review performed | **No** | process |

---

## Requirement 11 — Test Security Regularly

Intent: regular internal + external (ASV) scanning; periodic pen-testing + after significant change; wireless detection; IDS/IPS; change-detection on critical files (11.5.2).

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| Inspector continuous vuln scan + findings | Yes | `inspector2:BatchGetAccountStatus`,`ListFindings`,`ListCoverage` |
| GuardDuty (IDS-like) + findings | Yes | `guardduty:ListDetectors`,`GetDetector`,`ListFindings` |
| Security Hub + standards (CIS/PCI/FSBP) + findings | Yes | `securityhub:DescribeHub`,`GetEnabledStandards`,`DescribeStandardsControls`,`GetFindings` |
| Config rules as change/compliance detection (11.5) | Yes | `config:DescribeConfigRules`,`DescribeComplianceByConfigRule` |
| Config history (unauthorized change) | Yes | `config:GetResourceConfigHistory` |
| Network Firewall / WAF (IPS-adjacent) | Yes | `network-firewall:*`, `wafv2:*` |
| ASV external scans | **No (out of band)** | PCI SSC ASV reports; Inspector ≠ ASV |
| Pen test / segmentation test | **No** | external engagement |
| File-integrity monitoring (11.5.2) | **No (in-guest)** | Config is resource-config drift, not file-level `[ASSUMPTION]` |
| Rogue wireless detection (11.2) | **No** | physical/RF |

---

## Requirement 12 — Policy & Program

Intent: infosec policy & program; risk assessment; scope confirmation (≥annual + on significant change; SP ≥6-monthly); acceptable use; personnel security/awareness; TPSP management (responsibility matrices); tested IR plan.

| Signal | Collectable | boto3 → field |
|--------|-------------|---------------|
| Inventory currency (basis for 12.5.1 scope confirmation) | Yes (supports) | all service `Describe/List`; `config:ListDiscoveredResources` |
| Tagging governance (CDE/scope/owner) | Partial | `resourcegroupstaggingapi:GetResources`; org tag policies `[ASSUMPTION]` |
| Account/region footprint (scope surface) | Yes (supports) | `organizations:ListAccounts`, `account:ListRegions` |
| Untagged/unmanaged (scope-creep) | Yes | listings filtered for missing required tags |
| AWS as TPSP (AOC / responsibility matrix) | Partial (out of inventory) | **AWS Artifact** |
| Policy/risk-assessment/training/IR-testing/TPSP due diligence | **No** | documentation/process |

---

## Methodology notes

- Iterate **all enabled regions** and **all in-scope accounts**; single-region scans miss CDE resources.
- Many signals need **list-then-describe fan-out** (e.g., `GetBucketPolicy` per bucket, `GetKeyRotationStatus` per key).
- **Credential report** + **Access Analyzer** + **GetAccountAuthorizationDetails** are high-value, few-call sources for Req 7/8.
- Treat all results as **evidence inputs to QSA judgment**, never automated pass/fail.
