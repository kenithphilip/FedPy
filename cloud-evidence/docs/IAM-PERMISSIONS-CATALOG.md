# IAM / RBAC permission catalog

This catalog lists the **exact read-only permissions** each cloud-evidence collector
needs, organized by provider and KSI domain. Use it to:

1. Pre-build a least-privilege policy before the first run.
2. Diagnose an `AccessDenied` warning — find the failing collector below and grant
   the listed action/role.

> **Diagnostics tie-in.** When a collector hits a permission error, the warning it
> emits now names the required permission directly (see `core/error-diagnostics.ts`).
> This document is the authoritative reference if you want the full per-collector list.

All actions are **read-only**. The collector's runtime guardrails
(`core/readonly-guardrail.ts`, `core/readonly-guardrail-gcp.ts`) block any mutating
call regardless of what the IAM policy permits — but you should still grant only
read permissions so the *principal* is incapable of mutation.

---

## AWS

### Fastest path: AWS-managed `ReadOnlyAccess`

The AWS-managed `arn:aws:iam::aws:policy/ReadOnlyAccess` policy covers ~95% of the
actions below. Attach it, then add the small supplement in §AWS-supplement for the
handful of actions `ReadOnlyAccess` omits (mostly the `Generate*` report actions and
Organizations).

### Per-collector action map

| Collector (file) | KSIs | AWS service | Key actions |
|---|---|---|---|
| `iam.ts` | IAM-AAM, IAM-APM, IAM-ELP, IAM-JIT, IAM-MFA, IAM-SNU, IAM-SUS, CNA-DFP | IAM, Organizations, SSO-Admin, Identity Store, Access Analyzer, GuardDuty | `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListUsers`, `iam:GetUser`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`, `iam:ListMFADevices`, `iam:ListVirtualMFADevices`, `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:GetLoginProfile`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies`, `iam:ListAccountAliases`, `iam:ListSAMLProviders`, `iam:ListOpenIDConnectProviders`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`, `iam:SimulatePrincipalPolicy`, `sso:ListInstances`, `sso:ListPermissionSets`, `sso:DescribePermissionSet`, `sso:ListAccountAssignments`, `sso:DescribeInstanceAccessControlAttributeConfiguration`, `identitystore:ListUsers`, `identitystore:ListGroups`, `organizations:DescribeOrganization`, `organizations:ListAccounts`, `organizations:ListPolicies`, `organizations:DescribePolicy`, `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindings`, `guardduty:ListDetectors`, `guardduty:GetDetector` |
| `network.ts` | CNA-MAT, CNA-RNT, CNA-ULN, CNA-RVP, SVC-SNT | EC2, ELBv2, RDS, EKS, WAFv2, Shield, NetworkFirewall, Lambda | `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkAcls`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeFlowLogs`, `ec2:DescribeVpcEndpoints`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeTransitGateways`, `ec2:DescribeInstances`, `elasticloadbalancing:DescribeLoadBalancers`, `rds:DescribeDBInstances`, `eks:ListClusters`, `eks:DescribeCluster`, `wafv2:ListWebACLs`, `shield:GetSubscriptionState`, `network-firewall:ListFirewalls`, `lambda:ListFunctions`, `lambda:GetPolicy` |
| `config.ts` | CNA-EIS, CNA-IBP, SVC-ACM, SVC-EIS | Config, SecurityHub, CloudFormation | `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeConfigRules`, `config:DescribeRemediationConfigurations`, `config:DescribeConformancePacks`, `config:DescribeConformancePackCompliance`, `securityhub:GetEnabledStandards`, `cloudformation:DescribeStacks`, `cloudformation:DetectStackDrift` |
| `backup.ts` | CNA-OFA, RPL-ABO, RPL-TRC | Backup, DynamoDB, RDS | `backup:ListBackupPlans`, `backup:ListBackupJobs`, `backup:ListRestoreJobs`, `dynamodb:ListTables`, `dynamodb:DescribeContinuousBackups`, `rds:DescribeDBInstances` |
| `logging.ts` | MLA-ALA, MLA-EVC, MLA-LET, MLA-OSM, MLA-RVL, CMT-LMC, INR-RIR | CloudTrail, CloudWatch Logs, S3, Athena, Firehose, Security Lake, SecurityHub, CodeBuild | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:GetEventSelectors`, `cloudtrail:GetInsightSelectors`, `logs:DescribeLogGroups`, `logs:DescribeSubscriptionFilters`, `s3:GetBucketPolicy`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetObjectLockConfiguration`, `athena:ListWorkGroups`, `firehose:ListDeliveryStreams`, `securitylake:ListDataLakes`, `securitylake:ListSubscribers`, `securityhub:GetFindings`, `securityhub:GetEnabledStandards`, `codebuild:ListProjects` |
| `supplychain.ts` | CMT-RMV, CMT-VTD, SCR-MON | ECR, EC2, AutoScaling, Lambda, Signer, Inspector2 | `ecr:DescribeRepositories`, `ecr:DescribeImageScanFindings`, `ec2:DescribeLaunchTemplates`, `autoscaling:DescribeAutoScalingGroups`, `lambda:ListFunctions`, `lambda:GetFunctionCodeSigningConfig`, `signer:ListSigningProfiles`, `inspector2:ListFindings`, `inspector2:BatchGetAccountStatus` |
| `secrets.ts` | SVC-ASM | Secrets Manager, KMS | `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`, `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` |
| `data.ts` | SVC-RUD, SVC-VCM, SVC-VRI | S3, KMS, ACM, App Mesh, EKS, SSM | `s3:ListAllMyBuckets`, `s3:GetBucketVersioning`, `s3:GetBucketLifecycleConfiguration`, `s3:GetObjectLockConfiguration`, `kms:ListKeys`, `acm:ListCertificates`, `acm:DescribeCertificate`, `appmesh:ListMeshes`, `appmesh:ListVirtualNodes`, `eks:ListClusters`, `eks:ListAddons`, `ssm:GetPatchBaseline`, `lambda:GetFunctionCodeSigningConfig`, `signer:ListSigningProfiles` |
| `inventory.ts` | PIY-GIV | Config (aggregators) | `config:DescribeConfigurationAggregators`, `config:DescribeConfigurationRecorders` |
| `inventory-assets.ts` | Inventory Workbook (`--inventory-workbook`) | EC2, RDS, S3, Lambda, ELBv2, DynamoDB, ECR, EKS, CloudFront, SSM | `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeSecurityGroups`, `rds:DescribeDBInstances`, `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`, `lambda:ListFunctions`, `elasticloadbalancing:DescribeLoadBalancers`, `dynamodb:ListTables`, `dynamodb:DescribeTable`, `ecr:DescribeRepositories`, `eks:ListClusters`, `eks:DescribeCluster`, `cloudfront:ListDistributions`, `ssm:GetInventory` |
| `discover.ts` | Inventory backbone (`--inventory-workbook`) | Config, Resource Explorer, Tagging API | `config:SelectResourceConfig`, `resource-explorer-2:Search`, `tag:GetResources` (any one suffices; best-effort fallback chain) |
| `inventory-cost.ts` | Inventory cost + data-class (`--inventory-workbook`) | Cost Explorer, Macie | `ce:GetCostAndUsage`, `macie2:ListFindings`, `macie2:GetFindings` (both optional; degrade to warning if not enabled) |
| `reference-arch.ts` | Reference-arch audit (`--reference-arch`) | KMS, SecurityHub, NetworkFirewall, EC2, Organizations, CloudTrail, Backup, S3, DynamoDB | `kms:ListKeys`, `kms:DescribeKey`, `securityhub:GetEnabledStandards`, `network-firewall:ListFirewalls`, `ec2:DescribeFlowLogs`, `ec2:DescribeInstances`, `organizations:ListPolicies`, `organizations:ListDelegatedAdministrators`, `organizations:ListAWSServiceAccessForOrganization` (org checks: management account only — degrade to warning otherwise), `cloudtrail:DescribeTrails`, `backup:ListBackupPlans`, `backup:ListBackupSelections`, `s3:ListAllMyBuckets`, `s3:GetBucketEncryption`, `dynamodb:ListTables` (all covered by `ReadOnlyAccess`) |

### AWS-supplement (actions `ReadOnlyAccess` omits)

Attach this inline policy in addition to `ReadOnlyAccess`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GenerateCredentialReport",
      "iam:GenerateServiceLastAccessedDetails",
      "iam:SimulatePrincipalPolicy",
      "organizations:DescribeOrganization",
      "organizations:ListAccounts",
      "organizations:ListPolicies",
      "organizations:DescribePolicy",
      "sso:Describe*",
      "sso:List*",
      "identitystore:Describe*",
      "identitystore:List*",
      "access-analyzer:List*"
    ],
    "Resource": "*"
  }]
}
```

### Org fan-out (multi-account)

For `--aws-org-fanout`, the **management-account** principal additionally needs:
- `organizations:ListAccounts`, `organizations:DescribeOrganization`
- `sts:AssumeRole` on `arn:aws:iam::*:role/<cross-account-role>` (default `OrganizationAccountAccessRole`)

Each member-account role must itself hold `ReadOnlyAccess` + the supplement above.

---

## GCP

### Fastest path: predefined roles

Bind these predefined roles to the runner principal at the **org or folder** level:

| Role | Why |
|---|---|
| `roles/viewer` | Broad resource read (Compute, GKE, Cloud Run, etc.) |
| `roles/iam.securityReviewer` | IAM policy + service-account read (IAM-ELP, IAM-AAM) |
| `roles/logging.viewer` | Log sinks + metrics (MLA-ALA, MLA-LET) |
| `roles/cloudasset.viewer` | Asset inventory (PIY-GIV) |
| `roles/recommender.viewer` | IAM recommendations (IAM-ELP) |
| `roles/accesscontextmanager.policyReader` | VPC Service Controls perimeters (CNA-ULN, SVC-EIS) |

### Per-collector role/permission map

| Collector (file) | KSIs | GCP API | Required role / permission |
|---|---|---|---|
| `iam.ts` | IAM-* | IAM, Resource Manager, Recommender, Access Context Mgr, IAP, Identity Toolkit, PAM | `roles/iam.securityReviewer` (`iam.serviceAccounts.list`, `iam.serviceAccountKeys.list`, `iam.roles.list`, `resourcemanager.projects.getIamPolicy`), `roles/recommender.viewer`, `roles/accesscontextmanager.policyReader` |
| `network.ts` | CNA-*, SVC-SNT | Compute, Container (GKE) | `roles/compute.networkViewer` or `roles/viewer` (`compute.networks.list`, `compute.subnetworks.list`, `compute.firewalls.list`, `compute.securityPolicies.list`, `compute.sslPolicies.list`, `compute.targetHttpsProxies.list`, `compute.forwardingRules.list`, `container.clusters.list`) |
| `config.ts` | CNA-EIS, CNA-IBP, SVC-* | Org Policy, Security Command Center | `roles/orgpolicy.policyViewer` (`orgpolicy.policy.get`), `roles/securitycenter.findingsViewer` |
| `backup.ts` | CNA-OFA, RPL-* | Compute (snapshots), SQL Admin | `roles/viewer` (`compute.snapshots.list`, `cloudsql.instances.list`) |
| `logging.ts` | MLA-*, CMT-LMC, INR-RIR | Cloud Logging, Monitoring | `roles/logging.viewer` (`logging.sinks.list`, `logging.logMetrics.list`), `roles/monitoring.viewer` |
| `supplychain.ts` | CMT-RMV, CMT-VTD, SCR-MON | Artifact Registry, Binary Authorization, Container Analysis | `roles/artifactregistry.reader`, `roles/binaryauthorization.policyViewer`, `roles/containeranalysis.occurrences.viewer` |
| `secrets.ts` | SVC-ASM | Secret Manager, Cloud KMS | `roles/secretmanager.viewer`, `roles/cloudkms.viewer` |
| `data.ts` | SVC-RUD, SVC-VCM, SVC-VRI | Cloud Storage, KMS, Certificate Manager, Cloud Logging | `roles/storage.objectViewer` (bucket metadata), `roles/cloudkms.viewer`, `roles/certificatemanager.viewer`, `roles/logging.viewer` (deletion-event audit-log query; `roles/logging.privateLogViewer` if data-access logs) |
| `inventory.ts` | PIY-GIV | Cloud Asset Inventory | `roles/cloudasset.viewer` (`cloudasset.assets.listResource`) |
| `inventory-assets.ts` | Inventory Workbook (`--inventory-workbook`) | Cloud Asset Inventory (RESOURCE) | `roles/cloudasset.viewer` (`cloudasset.assets.list`) |
| `discover.ts` | Inventory backbone (`--inventory-workbook`) | Cloud Asset Inventory (search) | `roles/cloudasset.viewer` (`cloudasset.assets.searchAllResources`) |
| `reference-arch.ts` | Reference-arch audit (`--reference-arch`) | Assured Workloads, Org Policy, Access Context Mgr, Compute, Storage, Resource Manager, Security Command Center, DNS, Service Usage, SQL Admin | `roles/assuredworkloads.reader` (org), `roles/orgpolicy.policyViewer`, `roles/accesscontextmanager.policyReader` (org), `roles/compute.viewer`, `roles/storage.admin` or `roles/viewer`, `roles/iam.securityReviewer` (`resourcemanager.projects.getIamPolicy`, `resourcemanager.organizations.getIamPolicy`), `roles/securitycenter.adminViewer` (org), `roles/dns.reader`, `roles/serviceusage.serviceUsageViewer`, `roles/cloudsql.viewer`. Org-scoped checks degrade to a warning when no `organization_id` is configured. |

### GCP auth notes

- The runner uses **Application Default Credentials** (`gcloud auth application-default login`)
  or a service-account key via `GOOGLE_APPLICATION_CREDENTIALS`.
- The read-only OAuth scope `https://www.googleapis.com/auth/cloud-platform.read-only`
  is requested in `core/auth/gcp.ts`. This scope cannot grant write access even if the
  IAM role would otherwise allow it.

---

## Azure

### Fastest path: built-in roles (RBAC)

Assign these built-in roles to the runner principal at the **management group** scope (or
per-subscription if MG access isn't available):

| Role | Why |
|---|---|
| `Reader` | Broad ARM read across all resource types — includes Resource Graph (`Microsoft.ResourceGraph/resources/read`), Resources, Compute, Storage metadata, Networking, Key Vault metadata. |
| `Security Reader` | Defender for Cloud findings, secure-score recommendations, regulatory compliance assessments. |
| `Log Analytics Reader` | Read access to Log Analytics workspaces (diagnostic settings, queries). |
| `Storage Blob Data Reader` | Optional — only if a collector needs blob *contents* (not metadata). Inventory uses metadata only. |

### Per-collector role/permission map

| Collector (file) | KSIs / artifact | Azure service | Required role / permission |
|---|---|---|---|
| `auth/azure.ts` | whoAmI (token decode) | AAD | (none — token-only) |
| `discover.ts` | Inventory backbone (`--inventory-workbook`) | Resource Graph | `Reader` (`Microsoft.ResourceGraph/resources/read`) |
| `inventory-assets.ts` | Inventory depth (`--inventory-workbook`) | Resource Graph (Storage / Compute / NICs projections) | `Reader` (same as backbone — projections are KQL only) |

### Azure auth notes

- The collector uses `DefaultAzureCredential` from `@azure/identity`, which auto-discovers
  credentials in this order:
  `EnvironmentCredential` → `WorkloadIdentityCredential` → `ManagedIdentityCredential`
  → `AzureCliCredential` → `AzureDeveloperCliCredential` → `AzurePowerShellCredential`.
- For local runs the simplest setup is `az login`; for CI use a federated workload identity
  (GitHub OIDC + AAD app) or a service principal via env vars
  (`AZURE_TENANT_ID`/`AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`).
- Every Azure client we construct is wrapped in the read-only Proxy guardrail
  (`core/readonly-guardrail-azure.ts`) — defense in depth on top of the RBAC role.
  Disable with `CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL=1` only for debugging.

---

## Kubernetes

The K8s collector (`providers/k8s/security.ts`) needs **read** on RBAC resources.

### Fastest path: built-in `view` ClusterRole

```bash
kubectl create clusterrolebinding cloud-evidence-view \
  --clusterrole=view \
  --serviceaccount=<namespace>:<runner-sa>
```

`view` covers most reads but **excludes** `clusterrolebindings`/`clusterroles` reads
(those are intentionally not in `view`). Add a supplementary ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cloud-evidence-rbac-read
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterrolebindings", "clusterroles", "rolebindings", "roles"]
    verbs: ["get", "list"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["namespaces", "serviceaccounts", "pods"]
    verbs: ["get", "list"]
```

| Collector | KSI | K8s verbs needed |
|---|---|---|
| `security.ts::collectK8sIamElp` | IAM-ELP | `list` on `clusterrolebindings`, `clusterroles` (rbac.authorization.k8s.io) |

When the runner lacks these, the collector's warning names the exact resource +
verb (via `diagnoseK8sError`), e.g.
`rbac.listClusterRoleBinding 403 Forbidden — bind the runner ServiceAccount to a ClusterRole granting [list] on clusterrolebindings`.

---

## Full-level coverage collectors (Phase 4/5)

These collectors back the impact-level expansion (UCM crypto, VDR scan, the 7 KSI
hybrids). All calls are read-only.

### AWS

| Collector / KSI | AWS actions (read-only) |
|---|---|
| `crypto.ts` — KSI-AFR-UCM | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyPolicy`, `acm:ListCertificates`, `acm:DescribeCertificate`, `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`, `elasticloadbalancing:DescribeSSLPolicies`, `cloudfront:ListDistributions`, `cloudfront:GetDistribution` |
| `vdr-scan.ts` — KSI-AFR-VDR | `inspector2:BatchGetAccountStatus`, `inspector2:ListFindings` |
| `ksi-hybrids.ts` — KSI-CMT-RVP | `config:DescribeConfigRules`, `config:DescribeRemediationConfigurations`, `config:DescribeConformancePacks` |
| `ksi-hybrids.ts` — KSI-INR-AAR | `guardduty:ListDetectors`, `guardduty:GetDetector`, `events:ListRules`, `events:ListTargetsByRule` |
| `ksi-hybrids.ts` — KSI-INR-RPI | `cloudtrail:DescribeTrails`, `logs:DescribeLogGroups` |
| `ksi-hybrids.ts` — KSI-RPL-ARP | `rds:DescribeDBInstances`, `rds:DescribeDBClusters` |
| `ksi-hybrids.ts` — KSI-RPL-RRO | `backup:ListBackupPlans`, `backup:GetBackupPlan` |
| `ksi-hybrids.ts` — KSI-SCR-MIT | `ecr:GetRegistryScanningConfiguration`, `ecr:DescribeRepositories` |
| `ksi-hybrids.ts` — KSI-SVC-PRR | `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `rds:DescribeDBInstances` |

### GCP

| Collector / KSI | GCP roles / permissions (read-only) |
|---|---|
| `crypto.ts` — KSI-AFR-UCM | `cloudkms.cryptoKeys.list` (roles/cloudkms.viewer), `compute.sslPolicies.list` (roles/compute.viewer) |
| `vdr-scan.ts` — KSI-AFR-VDR | `containeranalysis.occurrences.list` (roles/containeranalysis.occurrences.viewer) |
| `ksi-hybrids.ts` — KSI-CMT-RVP | `cloudasset.feeds.list` (roles/cloudasset.viewer) |
| `ksi-hybrids.ts` — KSI-INR-AAR | `monitoring.alertPolicies.list` (roles/monitoring.viewer) |
| `ksi-hybrids.ts` — KSI-INR-RPI | `logging.sinks.list` (roles/logging.viewer) |
| `ksi-hybrids.ts` — KSI-RPL-ARP / RRO | `cloudsql.instances.list` (roles/cloudsql.viewer) |
| `ksi-hybrids.ts` — KSI-SCR-MIT | `binaryauthorization.policy.get` (roles/binaryauthorization.policyViewer) |
| `ksi-hybrids.ts` — KSI-SVC-PRR | `storage.buckets.list` (roles/storage.admin or roles/viewer), `cloudsql.instances.list` |

The ADS probe (`ADS-CSO-PUB`) needs only **outbound HTTPS** to your public endpoints;
MAS/SCG read operator-provided local files. None require cloud credentials.

## How permission errors surface at runtime

Every collector wraps its SDK calls in try/catch and emits a diagnostic warning via
`core/error-diagnostics.ts`. The warning classifies the error and tells you what to do:

| Error class | Example warning |
|---|---|
| `access_denied` | `aws:KSI-IAM-MFA AccessDenied — grant <action> to the runner IAM role (see RUNBOOK §2.1)` |
| `throttling` | `... throttled — raise CLOUD_EVIDENCE_RETRY_ATTEMPTS or run off-peak` |
| `not_found` | `... NotFound (often expected — resource doesn't exist)` |
| `not_enabled` | `... service not enabled in this account/region` |
| `network` | `... network error (ECONNRESET) — check VPC endpoints, DNS, proxy` |

These appear in:
- The per-KSI evidence file under `providers[*].warnings`
- The structured log (`event: collector.fail`, `err_class: <class>`)
- The coverage report (`out/coverage-report.json`) which flags KSIs with excess warnings

## Keeping this catalog current

This is a curated document. When you add a collector or a new SDK call:
1. Add the action/role to the relevant table above.
2. Pass the action name to `diagnoseAwsError(e, source, action)` in the collector's catch.

### Auto-generated cross-check

`docs/iam-actions.generated.json` is a machine-readable inventory of the
permissions the code *actually* references, produced by static analysis of the
provider source — AWS `*Command` imports → `<service>:<Action>`, and GCP
`roles/...` hints. Regenerate it with:

```bash
npm run gen:iam-actions          # node scripts/extract-iam-actions.mjs
node scripts/extract-iam-actions.mjs --check   # CI-style: exit 1 if stale
```

Use it to spot drift between this curated catalog and the live call sites (e.g.
a newly added collector that calls an action not yet documented here). It
currently inventories **145 AWS actions across 43 services** and **42 GCP roles**.
The extractor's pure helpers are unit-tested in
`tests/core/iam-actions-extract.test.ts`.
