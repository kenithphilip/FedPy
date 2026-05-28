# Research report: Coalfire-CF/Coalfire-AWS-RAMPpak

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/Coalfire-CF/Coalfire-AWS-RAMPpak
- **Local clone:** `research/clones/Coalfire-AWS-RAMPpak` (git-ignored)
- **Language / stack:** Terraform / HCL (IaC). AWS provider `~> 5.0`, Terraform `>= 1.5.0`. GovCloud-targeted (`us-gov-west-1`).
- **License:** **MIT** (`License.md`, Copyright 2023/2024 Coalfire Systems). Permissive — we may reuse text/config freely with attribution. But see §6: it's Terraform, not portable TS.
- **Activity / maturity:** Small parent repo (~50 files, 1.3 MB, shallow clone). Stable Coalfire OpenSource reference architecture; depends on versioned `terraform-aws-*` modules (pinned tags like `v0.0.20`, `v1.0.1`, `v0.0.6`).
- **One-line:** A "day-0 → networking → bastion" parent Terraform repo that composes Coalfire's `terraform-aws-<service>` modules to stand up a FedRAMP-compliant AWS (GovCloud) landing zone — i.e. a catalog of *what a compliant AWS environment should look like*.

## 1. What it does

RAMPpak is the **prescriptive counterpart to FedPy's detective role**. Where FedPy reads live AWS config and judges it against the 63 KSIs, RAMPpak *declares* the target state: it deploys an AWS Organization, a hardened management account, encrypted logging/state buckets, a segmented VPC with AWS Network Firewall, and a STIG-hardened bastion. The parent repo itself contains almost no resources — it's an **orchestration layer** that wires together separately-versioned Coalfire modules (`terraform-aws-account-setup`, `-organization`, `-vpc-nfw`, `-kms`, `-s3`, `-securitycore`, `-ec2`), feeding outputs from one stage into the next via S3 remote state.

It is organized as a **staged deployment** under `aws/terraform/us-gov-west-1/`:
`management-account/day0` → `org-creation` → `org-onboarding` → `networking` → `management-account/bastion` (the README's deploy order). Each stage README carries an explicit `FedRAMP Compliance: High` (or `Moderate, High`) tag, so the repo doubles as an impact-level-annotated control map.

The audience is FedRAMP CSPs / 3PAOs building a GovCloud boundary. For us, the value is not the Terraform itself but the **concrete, defensible configuration values** Coalfire (a top FedRAMP 3PAO) bakes in: KMS per service, 30-day log retention, NFW rule groups, CIS + AWS FSBP Security Hub standards, SCPs, dedicated firewall subnets, STIG AMIs. Each of these is a candidate **detective check** for our collectors.

## 2. Architecture & key components

Top-level layout (real paths from the clone):

- `README.md` — deploy order, MIT license, resource directory map.
- `aws/terraform/us-gov-west-1/global-vars.tf` — global defaults: `resource_prefix="pak"`, region `us-gov-west-1`, and a notable global tag `backup_policy = "aws-backup-minimum-compliance"` applied to all taggable resources.
- `management-account/day0/` — composes `terraform-aws-account-setup`. The README (`day0/README.md` lines 159–460) enumerates the **full module inventory**: per-service KMS keys, S3 buckets, CloudTrail.
- `org-creation/org.tf` — composes `terraform-aws-organization`: Security Hub standards, GuardDuty/Config/CloudTrail org integration, SCPs, delegated admin.
- `org-onboarding/` — `org-inv.tf` + `account_invite.sh`: cross-account role assumption (`mgmt_role_arn` + `external_id`) to invite member accounts.
- `networking/` — composes `terraform-aws-vpc-nfw`: VPC, 4 subnet tiers, NAT-per-AZ, VPC flow logs, AWS Network Firewall with four rule-group types (`nfw_policies.tf`, `locals.tf`, `subnets.tf`, `kms.tf`).
- `management-account/bastion/bastion.tf` — composes `terraform-aws-ec2`: a STIG-hardened Windows bastion with EBS KMS encryption.

**Module inventory (the `terraform-aws-<service>` coverage map)** — these double as a FedRAMP-relevant AWS service list our collectors should cover:

| Module | Stage | What it stands up |
|--------|-------|-------------------|
| `terraform-aws-account-setup` | day0 | KMS keys, S3 buckets, CloudTrail, Packer IAM, security-core |
| `terraform-aws-kms` (`v0.0.6`) | day0/net | Per-service CMKs (S3, EBS, RDS, DynamoDB, Lambda, SNS, Secrets Mgr, CloudWatch, Config, Backup, NFW) |
| `terraform-aws-s3` (`v1.0.1`) | day0 | accesslogs, backups, cloudtrail, config, elb-accesslogs, fedrampdoc, installs buckets |
| `terraform-aws-securitycore` | day0 | TF state S3 bucket + DynamoDB state-lock |
| `terraform-aws-organization` | org-creation | Org, SCPs, Security Hub, GuardDuty, Config multi-account |
| `terraform-aws-vpc-nfw` | networking | VPC, subnets, NAT, flow logs, Network Firewall |
| `terraform-aws-ec2` | bastion | STIG AMI EC2 + EBS encryption + SGs |

Data formats: pure HCL `.tf` + `.tfvars`; S3 backend state with DynamoDB locking; no OSCAL, no JSON evidence. Nothing portable to our TS detective directly.

## 3. What's genuinely interesting for FedPy

The signal is a set of **concrete, 3PAO-blessed config values** we can turn into pass/fail assertions:

- **Per-service KMS CMKs, not the AWS-managed default.** `day0/README.md` lines 177–196 create dedicated CMKs for *every* data service (S3, EBS, RDS, DynamoDB, Lambda, SNS, Secrets Manager, CloudWatch, Config, Backup, NFW). This is stronger than "encryption enabled" — it's "encrypted with a customer-managed key." A detective tool can verify the KMS key on each resource is customer-managed.
- **Security Hub with two named standards.** `org.tf` line 10 enables `cis-aws-foundations-benchmark/v/1.4.0` **and** `aws-foundational-security-best-practices/v/1.0.0`. We can check both are subscribed and at expected versions.
- **Org-level security services via `service_access_principals`.** `org-creation/README.md` lines 64–68: `cloudtrail`, `config`, `securityhub`, `guardduty`, `config-multiaccountsetup` are all org-trusted. Plus SCPs (`enabled_policy_types = ["SERVICE_CONTROL_POLICY"]`) and a delegated admin account.
- **AWS Network Firewall with layered rule groups.** `networking/locals.tf` defines stateless, five-tuple stateful, **domain (FQDN) denylist**, and **Suricata IPS** rule groups, with dedicated `firewall` subnets (`subnets.tf`). Egress FQDN filtering + IDS/IPS is rarely something we check today.
- **VPC flow logs → CloudWatch, KMS-encrypted, 30-day retention.** `networking/main.tf` lines 36–38. Both the *existence* of flow logs and their *encryption + retention* are assertable.
- **Dedicated firewall + 4-tier subnet segmentation.** `subnets.tf` carves firewall / public / compute / private tiers across 3 AZs — a concrete segmentation pattern to look for.
- **STIG-hardened golden AMI for bastion.** `bastion.tf` line 8 filters `Windows_Server-2019-English-STIG-Full-*`; EBS encrypted with a CMK (line 31). The "instances launched from a hardened/approved AMI" check is novel for us.
- **CloudTrail → CloudWatch with retention.** `day0/README.md` lines 114–118 + 202: org CloudTrail wired to a CloudWatch log group with `cloudwatch_log_group_retention_in_days = 30`.
- **Global backup tag.** `global-vars.tf` line 22: `backup_policy = "aws-backup-minimum-compliance"` — a tag-driven AWS Backup selection pattern we could detect for RPL coverage.
- **Encrypted, locked Terraform state.** Every `tstate.tf` uses `encrypt = true` + a DynamoDB `state-lock` table — an IaC-integrity signal (SCR domain).

## 4. Gaps in OUR stack this could fill

Mapping each to a concrete FedPy AWS collector surface (`cloud-evidence/providers/aws/*.ts`):

- **CMK-vs-AWS-managed-key depth.** Our `crypto.ts`/`data.ts` likely check "encryption on." RAMPpak shows the bar is *customer-managed* CMK per service. Gap: per-resource KMS key-manager verification.
- **Security Hub standard enrollment + version.** We may detect Security Hub presence; we likely don't assert the *specific* CIS 1.4.0 + FSBP 1.0.0 standards are enabled. Gap → `config.ts` / `logging.ts` (CMT/MLA).
- **Network Firewall / egress FQDN filtering / IPS.** `network.ts` covers SGs/NACLs/flow logs, but probably not AWS Network Firewall existence or Suricata/domain rule groups. Gap → `network.ts` (CNA-MAT/RNT).
- **Subnet-tier segmentation as a structural check.** We check routing/exposure; we likely don't assert a dedicated firewall subnet tier exists. Gap → `network.ts` (CNA).
- **Hardened/approved AMI provenance for running instances.** We have inventory (`inventory.ts`, PIY-GIV) but probably not "is this instance from a STIG/approved AMI." Gap → `inventory.ts`/`config.ts` (CMT/SCR).
- **VPC flow log retention + encryption (not just existence).** Strengthen existing `network.ts`/`logging.ts` flow-log check with retention-days + KMS assertions.
- **SCP presence + delegated-admin posture.** `iam.ts` covers identity; org-level SCP enforcement and delegated security admin are likely missing. Gap → `iam.ts` (IAM/governance).
- **Terraform-state integrity.** `supplychain.ts`/`config.ts` could detect the state bucket is encrypted + lock table present (SCR-MON style).

## 5. Integration opportunities (actionable)

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | Per-service **customer-managed CMK** check (S3/EBS/RDS/DynamoDB/Lambda/SNS/SM/CW/Config/Backup): assert resource encrypted *with a CMK*, not AWS-managed | `crypto.ts`, `data.ts` | For each resource, resolve its KMS key and verify `KeyManager == CUSTOMER` | idea | M | P0 |
| 2 | **Security Hub standards** subscribed = CIS AWS Foundations 1.4.0 + AWS FSBP 1.0.0 | `config.ts` / `logging.ts` (CMT/MLA) | `securityhub:GetEnabledStandards`; assert both ARNs present | idea | S | P0 |
| 3 | **AWS Network Firewall** present with stateful/Suricata/FQDN-denylist rule groups + dedicated firewall subnets | `network.ts` (CNA-MAT/RNT) | `network-firewall:ListFirewalls`/`DescribeFirewallPolicy`; check rule-group types | idea | M | P1 |
| 4 | **VPC flow logs**: existence **+ KMS-encrypted destination + retention ≥ 30d** | `network.ts` / `logging.ts` | `ec2:DescribeFlowLogs` + `logs:DescribeLogGroups` (retention/kmsKeyId) | idea | S | P1 |
| 5 | **Approved/STIG AMI provenance** for running EC2 (and EBS CMK-encrypted) | `inventory.ts` / `config.ts` (CMT/SCR) | `ec2:DescribeInstances` → AMI name/owner against an allow-pattern; check block-device KMS | idea | M | P1 |
| 6 | **Org SCPs enabled** + **delegated security admin** for GuardDuty/Config/Security Hub | `iam.ts` (governance) | `organizations:ListPolicies(SERVICE_CONTROL_POLICY)`, `ListDelegatedAdministrators` | idea | M | P1 |
| 7 | **Org-trusted security services** (CloudTrail/Config/SecurityHub/GuardDuty) via `ListAWSServiceAccessForOrganization` | `logging.ts`/`config.ts` | assert all five principals trusted | idea | S | P1 |
| 8 | **CloudTrail → CloudWatch** delivery + log-group retention | `logging.ts` (MLA/CMT-LMC) | `cloudtrail:GetTrail` (CloudWatchLogsLogGroupArn) + retention | idea | S | P1 |
| 9 | **Tag-driven AWS Backup** selection (`backup_policy` tag) coverage | `backup.ts` (RPL) | `backup:ListBackupSelections`; verify tag-based selection covers resources | idea | M | P2 |
| 10 | **Terraform/IaC state integrity**: state S3 bucket encrypted + DynamoDB lock table | `supplychain.ts`/`config.ts` (SCR-MON) | heuristic: detect `*-tf-state` bucket SSE + `*-state-lock` table | idea | M | P2 |
| 11 | Use the **module inventory (§2 table)** as a coverage checklist to confirm each FedRAMP-relevant AWS service has a collector | docs / coverage check | cross-reference against `ksi-map` | idea | S | P2 |

## 6. Risks, caveats, licensing

- **License: MIT, permissive** — compatible with our Apache-2.0; we can quote config values and reuse freely with attribution. Low risk.
- **Language mismatch is total.** This is Terraform/HCL declaring desired state; FedPy is TypeScript reading actual state. **Zero portable code** — value is 100% *ideas / config values*, not vendored modules. Do not attempt to "port" it.
- **GovCloud-specific defaults.** Region `us-gov-west-1`, ARNs use `aws-us-gov` partition, FIPS endpoints implied by GovCloud. Our checks must be partition-agnostic (commercial + GovCloud) — don't hardcode standard ARNs/regions from these examples.
- **Submodules not analyzed.** The real resource detail lives in the separate `terraform-aws-*` repos (not cloned per instructions). The parent repo + READMEs give the inventory and key values, but exact hardening (e.g., S3 public-access-block, bucket policies, IMDSv2 on EC2) is inside the submodules — a follow-up read of `terraform-aws-s3` / `terraform-aws-ec2` would sharpen checks #1 and #5.
- **Version drift.** Standards are pinned to older versions (CIS 1.4.0, FSBP 1.0.0). Our check should assert "a current/approved standard is enabled," not literally these versions, to avoid going stale.
- **Some example rules are illustrative, not compliant.** The NFW domain denylist example blocks `reddit.com`/`cnn.com`/`google.com` (`locals.tf`, `README.md`) — clearly placeholder content. Treat rule *structure* as the signal, not the specific domains.

## 7. Verdict

**Medium-high value as an idea source; invest a focused pass, borrow zero code.** RAMPpak is the clearest "what good looks like" AWS catalog we have — a 3PAO's own prescriptive config, MIT-licensed, mapping cleanly onto our existing AWS collectors. It yields **~11 candidate checks**, of which the single highest-value is **#1: verifying customer-managed CMKs per service** (it upgrades our entire encryption story from "encrypted" to "encrypted under a customer-controlled key," which is the actual FedRAMP bar) — closely followed by **#2 (Security Hub CIS+FSBP standards)** and **#3 (Network Firewall / egress FQDN filtering)** as net-new coverage. Use the §2 module inventory as a service-coverage checklist for our collectors. A worthwhile follow-up is a shallow read of `terraform-aws-s3` and `terraform-aws-ec2` to extract the bucket-policy / IMDSv2 specifics that live one layer down.
