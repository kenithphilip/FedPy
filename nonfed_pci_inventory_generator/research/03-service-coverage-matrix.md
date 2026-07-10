# 03 — AWS Service & Resource Coverage Matrix

> Every service/resource type to inventory, mapped to its **list/paginate** call and
> **describe/get** call, with pagination model, throttling profile, scope (regional vs **GLOBAL**),
> and the IAM permission required. **GLOBAL** services are collected **once** (region label
> `GLOBAL`), never per-region.
>
> **Pagination models:** `Paginator` (boto3 paginator available), `NextToken`/`Marker` (manual
> token), `None` (single response). **Throttling profile:** `Low` / `Med` / `High` (hard-throttling
> services get dedicated low concurrency caps). Permission column lists the dominant IAM action(s);
> the full least-privilege set is `SecurityAudit` + `ViewOnlyAccess` (see README / Phase deliverable).

Legend for "Scope": **R** = regional (collect per enabled region), **G** = GLOBAL (collect once).

---

## A. Compute

| Resource | List/paginate call | Describe/Get call | Pagination | Throttle | Scope | Key IAM |
|----------|--------------------|--------------------|------------|----------|-------|---------|
| EC2 instances | `ec2:DescribeInstances` | (same, full) | Paginator | Med | R | `ec2:DescribeInstances` |
| AMIs (owned) | `ec2:DescribeImages` (Owners=self) | (same) | None | Low | R | `ec2:DescribeImages` |
| EBS volumes | `ec2:DescribeVolumes` | (same) | Paginator | Med | R | `ec2:DescribeVolumes` |
| EBS snapshots (owned) | `ec2:DescribeSnapshots` (OwnerIds=self) | (same) | Paginator | Med | R | `ec2:DescribeSnapshots` |
| Auto Scaling groups | `autoscaling:DescribeAutoScalingGroups` | (same) | Paginator | Low | R | `autoscaling:Describe*` |
| Launch Templates | `ec2:DescribeLaunchTemplates` | `ec2:DescribeLaunchTemplateVersions` | Paginator | Low | R | `ec2:DescribeLaunchTemplate*` |
| Launch Configurations | `autoscaling:DescribeLaunchConfigurations` | (same) | Paginator | Low | R | `autoscaling:Describe*` |
| Lambda functions | `lambda:ListFunctions` | `lambda:GetFunction`, `GetPolicy`, `GetFunctionConfiguration` | Paginator | Med | R | `lambda:List*`,`lambda:Get*` |
| ECS clusters/services/tasks | `ecs:ListClusters`→`ListServices`/`ListTasks` | `ecs:DescribeClusters/Services/Tasks/TaskDefinition` | Paginator | Med | R | `ecs:List*`,`ecs:Describe*` |
| EKS clusters | `eks:ListClusters` | `eks:DescribeCluster`, `ListNodegroups`→`DescribeNodegroup` | Paginator | Low | R | `eks:List*`,`eks:Describe*` |
| ECR repositories | `ecr:DescribeRepositories` | `ecr:GetRepositoryPolicy`, `ListImages` | Paginator | Med | R | `ecr:Describe*`,`ecr:List*`,`ecr:Get*` |
| Batch | `batch:DescribeComputeEnvironments`,`DescribeJobQueues` | (same) | NextToken | Low | R | `batch:Describe*` |
| Lightsail | `lightsail:GetInstances`,`GetLoadBalancers`,`GetDatabases` | (same) | NextToken | Low | R | `lightsail:Get*` |
| Elastic Beanstalk | `elasticbeanstalk:DescribeEnvironments`,`DescribeApplications` | `DescribeConfigurationSettings` | None | Low | R | `elasticbeanstalk:Describe*` |

## B. Networking

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| VPCs | `ec2:DescribeVpcs` | (same) | Paginator | Med | R | `ec2:DescribeVpcs` |
| Subnets | `ec2:DescribeSubnets` | (same) | Paginator | Med | R | `ec2:DescribeSubnets` |
| Route tables | `ec2:DescribeRouteTables` | (same) | Paginator | Med | R | `ec2:DescribeRouteTables` |
| Internet gateways | `ec2:DescribeInternetGateways` | (same) | Paginator | Low | R | `ec2:Describe*` |
| NAT gateways | `ec2:DescribeNatGateways` | (same) | Paginator | Low | R | `ec2:DescribeNatGateways` |
| Egress-only IGW | `ec2:DescribeEgressOnlyInternetGateways` | (same) | Paginator | Low | R | `ec2:Describe*` |
| VPC peering | `ec2:DescribeVpcPeeringConnections` | (same) | Paginator | Low | R | `ec2:Describe*` |
| Transit gateways | `ec2:DescribeTransitGateways`,`DescribeTransitGatewayAttachments` | (same) | Paginator | Low | R | `ec2:DescribeTransitGateway*` |
| ENIs | `ec2:DescribeNetworkInterfaces` | (same) | Paginator | Med | R | `ec2:DescribeNetworkInterfaces` |
| Elastic IPs | `ec2:DescribeAddresses` | (same) | None | Low | R | `ec2:DescribeAddresses` |
| Security groups | `ec2:DescribeSecurityGroups` | (same) | Paginator | Med | R | `ec2:DescribeSecurityGroups` |
| Network ACLs | `ec2:DescribeNetworkAcls` | (same) | Paginator | Med | R | `ec2:DescribeNetworkAcls` |
| VPC endpoints | `ec2:DescribeVpcEndpoints` | (same) | Paginator | Low | R | `ec2:DescribeVpcEndpoints` |
| VPC Flow Logs (config) | `ec2:DescribeFlowLogs` | (same) | Paginator | Low | R | `ec2:DescribeFlowLogs` |
| Direct Connect | `directconnect:DescribeConnections`,`DescribeVirtualInterfaces` | (same) | None | Low | R | `directconnect:Describe*` |
| Site-to-Site VPN | `ec2:DescribeVpnConnections`,`DescribeVpnGateways` | (same) | None | Low | R | `ec2:DescribeVpn*` |
| Client VPN | `ec2:DescribeClientVpnEndpoints` | (same) | Paginator | Low | R | `ec2:DescribeClientVpn*` |

## C. Edge / Exposure

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| ALB/NLB (v2) | `elbv2:DescribeLoadBalancers` | `DescribeListeners`,`DescribeTargetGroups`,`DescribeTargetHealth`,`DescribeListenerCertificates` | Paginator | Med | R | `elasticloadbalancing:Describe*` |
| Classic ELB | `elb:DescribeLoadBalancers` | `DescribeLoadBalancerPolicies` | Paginator | Med | R | `elasticloadbalancing:Describe*` |
| API Gateway REST | `apigateway:GetRestApis` | `GetStages`,`GetResources`,`GetDomainNames` | Paginator | **High** | R | `apigateway:GET` |
| API Gateway HTTP/WS (v2) | `apigatewayv2:GetApis` | `GetStages`,`GetRoutes` | NextToken | **High** | R | `apigateway:GET` |
| CloudFront | `cloudfront:ListDistributions` | `GetDistributionConfig` | Paginator | Low | **G** | `cloudfront:List*`,`Get*` |
| Global Accelerator | `globalaccelerator:ListAccelerators` | `DescribeAccelerator`,`ListListeners` | Paginator | Low | **G** (us-west-2 endpoint) | `globalaccelerator:List*`,`Describe*` |
| Route 53 hosted zones | `route53:ListHostedZones` | `ListResourceRecordSets` | Paginator | Med | **G** | `route53:List*`,`Get*` |
| Route 53 health checks | `route53:ListHealthChecks` | (same) | Paginator | Low | **G** | `route53:List*` |
| WAF (global/CloudFront) | `wafv2:ListWebACLs` (Scope=CLOUDFRONT) | `GetWebACL` | NextToken | Low | **G** (us-east-1) | `wafv2:List*`,`Get*` |
| WAFv2 (regional) | `wafv2:ListWebACLs` (Scope=REGIONAL) | `GetWebACL` | NextToken | Low | R | `wafv2:List*`,`Get*` |
| WAF Classic | `waf:ListWebACLs` / `waf-regional:ListWebACLs` | `GetWebACL` | NextToken | Low | G / R | `waf:List*`,`Get*` |
| Shield | `shield:ListProtections`,`DescribeSubscription` | (same) | NextToken | Low | **G** | `shield:List*`,`Describe*` |

## D. Storage

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| S3 buckets | `s3:ListBuckets` | `GetBucketLocation`,`GetBucketEncryption`,`GetBucketPolicy`,`GetBucketPolicyStatus`,`GetPublicAccessBlock`,`GetBucketAcl`,`GetBucketVersioning`,`GetBucketLogging`,`GetBucketTagging` | None (list) | Med | **G** namespace; per-bucket region noted | `s3:ListAllMyBuckets`,`s3:GetBucket*`,`s3:GetEncryptionConfiguration` |
| S3 Access Points | `s3control:ListAccessPoints` | `GetAccessPoint` | NextToken | Low | R | `s3:ListAccessPoints` |
| EFS | `efs:DescribeFileSystems` | `DescribeMountTargets`,`DescribeFileSystemPolicy` | Paginator | Low | R | `elasticfilesystem:Describe*` |
| FSx | `fsx:DescribeFileSystems` | (same) | Paginator | Low | R | `fsx:Describe*` |
| Storage Gateway | `storagegateway:ListGateways` | `DescribeGatewayInformation` | Paginator | Low | R | `storagegateway:List*`,`Describe*` |
| AWS Backup | `backup:ListBackupVaults`,`ListBackupPlans` | `GetBackupVaultAccessPolicy`,`GetBackupPlan` | Paginator | Low | R | `backup:List*`,`Get*` |

## E. Databases

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| RDS instances | `rds:DescribeDBInstances` | (same) | Paginator | Med | R | `rds:Describe*` |
| RDS/Aurora clusters | `rds:DescribeDBClusters` | (same) | Paginator | Med | R | `rds:Describe*` |
| RDS snapshots | `rds:DescribeDBSnapshots`,`DescribeDBClusterSnapshots` | (same) | Paginator | Med | R | `rds:Describe*` |
| DynamoDB | `dynamodb:ListTables` | `DescribeTable`,`DescribeContinuousBackups` | Paginator | Med | R | `dynamodb:List*`,`Describe*` |
| ElastiCache | `elasticache:DescribeCacheClusters`,`DescribeReplicationGroups` | (same) | Paginator | Low | R | `elasticache:Describe*` |
| Redshift | `redshift:DescribeClusters` | (same) | Paginator | Low | R | `redshift:Describe*` |
| DocumentDB | (via `rds` engine=docdb) `rds:DescribeDBClusters` | (same) | Paginator | Low | R | `rds:Describe*` |
| Neptune | (via `rds` engine=neptune) | (same) | Paginator | Low | R | `rds:Describe*` |
| MemoryDB | `memorydb:DescribeClusters` | (same) | NextToken | Low | R | `memorydb:Describe*` |
| Timestream | `timestream-write:ListDatabases` | `ListTables` | NextToken | Low | R | `timestream:List*`,`Describe*` |
| QLDB | `qldb:ListLedgers` | `DescribeLedger` | NextToken | Low | R | `qldb:List*`,`Describe*` |

## F. IAM & Access — **GLOBAL** (collect once)

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| Users | `iam:ListUsers` | `GetUser`,`ListAccessKeys`,`GetAccessKeyLastUsed`,`ListMFADevices`,`ListGroupsForUser`,`ListAttachedUserPolicies`,`ListUserPolicies` | Paginator | **High** | **G** | `iam:List*`,`iam:Get*` |
| Groups | `iam:ListGroups` | `ListAttachedGroupPolicies`,`ListGroupPolicies`,`GetGroup` | Paginator | High | **G** | `iam:List*`,`Get*` |
| Roles | `iam:ListRoles` | `GetRole`,`ListAttachedRolePolicies`,`ListRolePolicies`,`GetRolePolicy` | Paginator | High | **G** | `iam:List*`,`Get*` |
| Managed policies | `iam:ListPolicies` (Scope=Local + AWS as needed) | `GetPolicy`,`GetPolicyVersion` | Paginator | High | **G** | `iam:List*`,`Get*` |
| Instance profiles | `iam:ListInstanceProfiles` | `GetInstanceProfile` | Paginator | High | **G** | `iam:List*`,`Get*` |
| Account password policy | `iam:GetAccountPasswordPolicy` | (same) | None | Low | **G** | `iam:GetAccountPasswordPolicy` |
| Account summary / aliases | `iam:GetAccountSummary`,`ListAccountAliases` | (same) | None | Low | **G** | `iam:Get*`,`List*` |
| Credential report | `iam:GenerateCredentialReport`→`GetCredentialReport` | (same) | None | Low | **G** | `iam:GenerateCredentialReport`,`GetCredentialReport` |
| Root usage indicators | (from credential report + `GetAccountSummary`) | — | — | Low | **G** | as above |
| SAML/OIDC providers | `iam:ListSAMLProviders`,`ListOpenIDConnectProviders` | `Get*Provider` | None | Low | **G** | `iam:List*`,`Get*` |
| IAM Identity Center (SSO) | `sso-admin:ListInstances`→`ListPermissionSets` | `DescribePermissionSet` | NextToken | Low | R (regional service, single home) | `sso:List*`,`Describe*`,`identitystore:List*` |
| Identity Store | `identitystore:ListUsers`,`ListGroups` | (same) | NextToken | Low | R | `identitystore:List*` |
| Cognito user pools | `cognito-idp:ListUserPools` | `DescribeUserPool`,`GetUserPoolMfaConfig` | Paginator | Low | R | `cognito-idp:List*`,`Describe*` |
| Cognito identity pools | `cognito-identity:ListIdentityPools` | `DescribeIdentityPool` | Paginator | Low | R | `cognito-identity:List*`,`Describe*` |
| Access Analyzer | `accessanalyzer:ListAnalyzers`,`ListFindings` | `GetAnalyzer` | NextToken | Low | R | `access-analyzer:List*`,`Get*` |

> **IAM throttling is severe.** Prefer the **credential report** (one call) for users' key/MFA/last-used
> data and cap IAM worker concurrency to 1–2.

## G. Security & Crypto

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| KMS keys | `kms:ListKeys`,`ListAliases` | `DescribeKey`,`GetKeyRotationStatus`,`GetKeyPolicy`,`ListGrants` | Paginator | Med | R | `kms:List*`,`Describe*`,`GetKeyRotationStatus`,`GetKeyPolicy` |
| CloudHSM | `cloudhsmv2:DescribeClusters` | (same) | NextToken | Low | R | `cloudhsm:Describe*` |
| ACM certs | `acm:ListCertificates` | `DescribeCertificate` | Paginator | Med | R | `acm:List*`,`Describe*` |
| ACM PCA | `acm-pca:ListCertificateAuthorities` | `DescribeCertificateAuthority` | NextToken | Low | R | `acm-pca:List*`,`Describe*` |
| Secrets Manager | `secretsmanager:ListSecrets` | `DescribeSecret`,`GetResourcePolicy` | Paginator | Med | R | `secretsmanager:List*`,`DescribeSecret`,`GetResourcePolicy` |
| SSM Parameters | `ssm:DescribeParameters` | (metadata only; **never GetParameter values**) | Paginator | Med | R | `ssm:DescribeParameters` |
| GuardDuty | `guardduty:ListDetectors` | `GetDetector`,`ListFindings`(count) | Paginator | Low | R | `guardduty:List*`,`Get*` |
| Security Hub | `securityhub:DescribeHub`,`GetEnabledStandards` | `DescribeStandardsControls` | NextToken | Low | R | `securityhub:Describe*`,`Get*` |
| Inspector2 | `inspector2:BatchGetAccountStatus`,`ListCoverage` | (same) | NextToken | Low | R | `inspector2:List*`,`BatchGet*` |
| Macie | `macie2:GetMacieSession`,`DescribeBuckets` | (same) | NextToken | Low | R | `macie2:Get*`,`Describe*` |
| Detective | `detective:ListGraphs` | (same) | NextToken | Low | R | `detective:List*` |
| Audit Manager | `auditmanager:GetSettings`,`ListAssessments` | (same) | NextToken | Low | R | `auditmanager:Get*`,`List*` |

> **SSM SecureString:** capture parameter **name/type/metadata only**; never call `GetParameter`
> with decryption. Recorded as existence evidence.

## H. Logging & Monitoring

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| CloudTrail trails | `cloudtrail:DescribeTrails`,`ListTrails` | `GetTrailStatus`,`GetEventSelectors`,`GetInsightSelectors` | None/NextToken | **Med-High** | R (multi-region trails flagged) | `cloudtrail:DescribeTrails`,`GetTrailStatus`,`GetEventSelectors` |
| CloudWatch Log groups | `logs:DescribeLogGroups` | `ListTagsForResource`,`DescribeMetricFilters` | Paginator | Med | R | `logs:Describe*` |
| CloudWatch Alarms | `cloudwatch:DescribeAlarms` | (same) | Paginator | Med | R | `cloudwatch:Describe*` |
| Config recorders | `config:DescribeConfigurationRecorders`,`DescribeConfigurationRecorderStatus` | (same) | None | **High** | R | `config:Describe*` |
| Config rules | `config:DescribeConfigRules` | `DescribeComplianceByConfigRule` | NextToken | **High** | R | `config:Describe*` |
| Config conformance packs | `config:DescribeConformancePacks` | (same) | NextToken | High | R | `config:Describe*` |
| EventBridge rules | `events:ListRules` | `ListTargetsByRule` | NextToken | Low | R | `events:List*` |
| EventBridge buses | `events:ListEventBuses` | (same) | NextToken | Low | R | `events:List*` |

> **Config & CloudTrail throttle hard** — dedicated low concurrency caps.

## I. Management / Org — **GLOBAL** unless noted

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| Organizations accounts | `organizations:ListAccounts` | `DescribeOrganization`,`DescribeAccount` | Paginator | **High** | **G** (mgmt/deleg-admin only) | `organizations:List*`,`Describe*` |
| Org OUs / roots | `organizations:ListRoots`,`ListOrganizationalUnitsForParent` | `DescribeOrganizationalUnit` | Paginator | High | **G** | `organizations:List*`,`Describe*` |
| SCPs | `organizations:ListPolicies`(SERVICE_CONTROL_POLICY) | `DescribePolicy`,`ListTargetsForPolicy` | Paginator | High | **G** | `organizations:List*`,`Describe*` |
| Control Tower | `controltower:ListEnabledControls`,`ListLandingZones` | (same) | NextToken | Low | R | `controltower:List*` |
| Enabled regions | `account:ListRegions` / `ec2:DescribeRegions` | (same) | None | Low | **G** | `ec2:DescribeRegions`,`account:ListRegions` |
| Trusted Advisor | `support:DescribeTrustedAdvisorChecks`/`...CheckResult` | (same) | None | Low | **G** (Business+ support) | `support:Describe*` |
| Health | `health:DescribeEvents` | (same) | Paginator | Low | **G** (Business+ support) | `health:Describe*` |

> **Trusted Advisor / Health** require Business/Enterprise Support; otherwise `NOT_COLLECTED` with note.

## J. Messaging / Integration (security-impacting)

| Resource | List/paginate | Describe/Get | Pagination | Throttle | Scope | Key IAM |
|----------|---------------|--------------|------------|----------|-------|---------|
| SNS topics | `sns:ListTopics` | `GetTopicAttributes` | Paginator | Med | R | `sns:List*`,`GetTopicAttributes` |
| SQS queues | `sqs:ListQueues` | `GetQueueAttributes` | NextToken | Med | R | `sqs:List*`,`GetQueueAttributes` |
| Kinesis streams | `kinesis:ListStreams` | `DescribeStreamSummary` | NextToken | Low | R | `kinesis:List*`,`Describe*` |
| Step Functions | `stepfunctions:ListStateMachines` | `DescribeStateMachine` | Paginator | Low | R | `states:List*`,`Describe*` |
| Amazon MQ | `mq:ListBrokers` | `DescribeBroker` | NextToken | Low | R | `mq:List*`,`Describe*` |

---

## Pre-scan region indicator probe (for unused-region detection)

A region is judged **in use** if any indicator probe returns >0 (cheap calls only):
1. `ec2:DescribeInstances` (MaxResults small, any state) > 0
2. `ec2:DescribeVpcs` non-default VPC present (`isDefault=false`)
3. `ec2:DescribeNetworkInterfaces` > 0
4. `rds:DescribeDBInstances` > 0
5. `lambda:ListFunctions` > 0
6. `s3` buckets located in region (from global bucket list + `GetBucketLocation`)
7. `cloudtrail:LookupEvents`/trail recent activity **[ASSUMPTION — optional, can be costly; default off]**

If all indicators are empty → region marked **"no resources detected — excluded"** (still recorded
in Regions Coverage). Overridable via `--all-regions` / `--include-empty-regions`.

---

## Global-service collection rule (must-not-duplicate)

Collect **once**, labelled `region="GLOBAL"`:
- IAM (all), Organizations (all), Route 53, CloudFront, Global Accelerator,
  WAF/WAFv2 **CLOUDFRONT scope** (us-east-1), Shield, S3 bucket **namespace** (list once;
  per-bucket attributes fetched against the bucket's home region), `account:ListRegions`.

Regional services iterate only over **included** regions.

---

## Throttle-class concurrency caps (defaults, configurable)

| Class | Services | Default cap |
|-------|----------|-------------|
| Hard | IAM, Organizations, Config, API Gateway, CloudTrail | 1–2 |
| Medium | EC2, RDS, Lambda, ELB, KMS, S3, DynamoDB, logs | 4–6 |
| Low | everything else | up to global worker cap |

Plus boto3 `retries={'mode':'adaptive','max_attempts':N}` and a global token-bucket that backs off
on `Throttling` / `RequestLimitExceeded` / `TooManyRequestsException`.
