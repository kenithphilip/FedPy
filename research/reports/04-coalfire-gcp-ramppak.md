# Research report: Coalfire-CF/Coalfire-GCP-RAMPpak

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/Coalfire-CF/Coalfire-GCP-RAMPpak
- **Local clone:** `research/clones/Coalfire-GCP-RAMPpak` (git-ignored)
- **Language / stack:** Terraform / HCL (IaC). Google provider pinned `4.70.0` (+ `google-beta`), Terraform `1.5.0`, `gcloud` `435.0.0`, GCS remote-state backend. Targets **Assured Workloads / FedRAMP Moderate, US region** (`us-east1` default).
- **License:** **MIT** (`License.md`, Copyright 2023/2024 Coalfire Systems, Inc.). Permissive — compatible with our Apache-2.0; we can quote config values and reuse freely with attribution. But see §6: it is Terraform, not portable TS — **idea source only**.
- **Activity / maturity:** Very small parent repo (~37 files, 524 KB, shallow clone). Last commit `9ef241c` (2026-02-05, "readme-updates"). Stable Coalfire OpenSource reference architecture; depends on un-pinned (`n/a` version) `github.com/Coalfire-CF/terraform-google-<service>` modules referenced by branch, plus public `hashicorp/subnets/cidr`. Submodules were **not** cloned per instructions.
- **One-line:** A "security-core → networking → bastions" parent Terraform repo that composes Coalfire's `terraform-google-<service>` modules to stand up a FedRAMP-Moderate GCP landing zone inside an Assured Workloads folder — i.e. a catalog of *what a compliant GCP environment should look like*.

## 1. What it does

GCP RAMPpak is the **prescriptive counterpart to FedPy's detective role**, on the GCP side. Where FedPy's `cloud-evidence/providers/gcp/*.ts` collectors read live GCP config (via `googleapis` + ADC behind a read-only Proxy) and judge it against the 63 KSIs / 223 requirements, RAMPpak *declares* the target state: it bootstraps a GCP Organization, creates folders/projects under an **Assured Workloads** folder, activates a curated API set, mints **per-service Cloud KMS CMEK keys**, stands up encrypted GCS state/install/backup buckets, wires an **organization log sink**, applies **organization policies**, enables **audit logging**, then builds a three-tier shared-VPC network and a CMEK-encrypted Windows bastion.

The parent repo itself contains almost no resources — it is an **orchestration layer** that wires together separately-maintained Coalfire modules (`terraform-google-security-core`, `-network`, `-cloud-router`, `-vm`, `-service-account`, `ACE-GCP-Private-Service-Access`), feeding outputs from one stage into the next via **GCS remote state** (`terraform_remote_state.security_core` / `.networking`).

It is organized as a **staged deployment** under `organization/`: `security_core` → `networking` → `bastions` (the README "Deployment Order of Operations"). A critical FedRAMP-specific prerequisite is documented up front: because **Google has no GovCloud equivalent, FedRAMP compliance on GCP requires an Assured Workloads folder** (`Compliance type: FedRAMP Moderate`, `Region: US`) created before any Terraform runs. The audience is FedRAMP CSPs / 3PAOs building a GCP boundary. For us, the value is not the Terraform but the **concrete, defensible GCP control configurations** Coalfire (a top FedRAMP 3PAO) bakes in — each a candidate **detective check** for our GCP collectors.

## 2. Architecture & key components

Top-level layout (real paths from the clone):

- `README.md` — deploy order, tooling/versions, **Assured Workloads prerequisite**, org-admin group + IAM-role bootstrap, MIT license.
- `organization/security_core/` — composes `terraform-google-security-core` (`main.tf`). The README (`security_core/README.md`) enumerates what it creates: **folders/projects under Assured Workloads, API enablement, CMEK keys, GCS buckets (state/installs/backups), an org log sink + destination, organization policies, audit logging.** `variables.tf` carries the curated API allow-lists; `outputs.tf` exposes four per-service KMS key IDs (`compute-engine`, `secret-manager`, `cloud-storage`, `cloud-sql`).
- `organization/networking/` — composes `terraform-google-network` (×3: public/management/private), `terraform-google-cloud-router` (NAT), `ACE-GCP-Private-Service-Access`, network-peering, and `hashicorp/subnets/cidr`. Concrete committed resources: `dns.tf` (DNS policy with logging + inbound forwarding), `nat.tf` (Cloud NAT), `network.tf` (3 VPCs, shared-VPC host, peering, **internal L7 LB proxy subnet**, private service access), `subnets.tf` (segmented subnet plan), `firewall.tf` (ingress rules).
- `organization/bastions/` — composes `terraform-google-vm` + `terraform-google-service-account`. `bastion-windows-vm.tf` (CMEK-encrypted disk, premium NAT IP, least-scope SA), `bastion-iam.tf` (narrowly-scoped service-account roles).
- `.github/workflows/org-checkov.yml` — runs **Checkov** IaC scanning on every `**.tf` PR (reusable Coalfire org workflow). Also `org-terraform-docs.yml`, `org-md-lint.yml`, `org-release.yml`.

**Module inventory (the `terraform-google-<service>` coverage map)** — doubles as a FedRAMP-relevant GCP service list our collectors should cover:

| Module | Stage | What it stands up |
|--------|-------|-------------------|
| `terraform-google-security-core` | security_core | Folders/projects, API enablement, **CMEK keys**, GCS buckets, **org log sink**, **org policies**, **audit logging** |
| `terraform-google-network` | networking | VPCs, subnets, shared-VPC host/service, firewall-rules + network-peering submodules |
| `terraform-google-cloud-router` | networking | Cloud Router + **Cloud NAT** (dynamic port alloc) |
| `ACE-GCP-Private-Service-Access` | networking | **Private Service Access** peering range for managed services (Cloud SQL etc.) |
| `terraform-google-vm` | bastions | Compute Engine VM, **CMEK disk encryption** |
| `terraform-google-service-account` | bastions | Least-privilege service account + project-role bindings |
| `hashicorp/subnets/cidr` (public) | networking | Deterministic subnet CIDR carving |

Curated **API enablement allow-lists** (`security_core/variables.tf`) are themselves a control signal (only-needed-services / attack-surface reduction):

- *management project*: `cloudkms`, `compute`, `logging`, `monitoring`, `pubsub`, `secretmanager`, `servicenetworking`, `sourcerepo`.
- *networking project*: `compute`, `dns`, `logging`, `servicenetworking`.

Data formats: pure HCL `.tf` + `.tfvars`; GCS backend state; no OSCAL, no JSON evidence. **Nothing portable to our TS detective directly.**

## 3. What's genuinely interesting for FedPy

The signal is a set of **concrete, 3PAO-blessed GCP config values** we can turn into pass/fail assertions:

- **Assured Workloads as a hard FedRAMP prerequisite.** `README.md` lines 35–40: a `FedRAMP Moderate` Assured Workloads folder, `Region: US`, is mandatory before anything. This is the single highest-signal GCP-specific control and is **structurally absent from AWS** (no GovCloud analog). A detective tool can verify projects live under an Assured Workloads folder with the right compliance regime + region.
- **Per-service Cloud KMS CMEK, not Google-managed default.** `security_core/outputs.tf` exposes dedicated keys for `compute-engine`, `secret-manager`, `cloud-storage`, `cloud-sql`. The bastion disk consumes `gce_kms_key_id` (`bastion-windows-vm.tf` line 19: `disk_encryption_key = ...gce_kms_key_id`). The bar is **CMEK per service**, not "encryption enabled."
- **Organization Policy constraints.** `security_core/README.md` line 11: "Configure organization policies." Org policies (e.g. `compute.requireOsLogin`, `iam.disableServiceAccountKeyCreation`, `storage.uniformBucketLevelAccess`, `compute.vmExternalIpAccess`, `gcp.resourceLocations`, `sql.restrictPublicIp`) are the GCP equivalent of AWS SCPs and a core FedRAMP-GCP control. **High-signal — see §4.**
- **Organization log sink + destination + audit logging.** `security_core/README.md` lines 9, 11: an *org-level* aggregated log sink to a destination (typically a CMEK GCS bucket / BigQuery / Pub/Sub) plus enabled audit logging (Admin Activity always-on; Data Access must be explicitly enabled). Existence + destination + audit-log-config are all assertable.
- **DNS query logging + inbound forwarding.** `networking/dns.tf`: `google_dns_policy.dns_logging` with `enable_logging = true` attached to all three VPCs. DNS query logging is a discrete MLA-type evidence source we likely do not check.
- **Shared VPC + three-tier segmentation.** `network.tf`: separate `public`, `management` (shared-VPC host), `private` VPCs; the private VPC carves *purpose-named* subnets (`iam`, `cicd`, `secops`, `siem`, `monitoring`, `dmz`, plus `firewall`, `proxy`, `psa`) (`subnets.tf`). Shared-VPC host/service-project relationships (`google_compute_shared_vpc_service_project`) are a concrete governance structure.
- **Private Service Access + internal L7 LB proxy subnet.** `network.tf` lines 85–107: a `psa` peering range for managed services and an `INTERNAL_HTTPS_LOAD_BALANCER` proxy-only subnet — keeps managed services (Cloud SQL) off public IPs.
- **Cloud NAT instead of public egress IPs.** `nat.tf`: Cloud Router + NAT with `enable_dynamic_port_allocation = true` and `enable_endpoint_independent_mapping = false` (the security-recommended NAT setting). Private nodes get egress without external IPs.
- **Least-privilege bastion service account.** `bastion-iam.tf`: bastion SA granted exactly four narrow roles (`secretmanager.secretAccessor`, `source.reader`, `logging.logWriter`, `monitoring.metricWriter`) — no broad/primitive roles. A concrete "no over-privileged SA" pattern.
- **Restricted org-admin group with security label.** `README.md` lines 24–34: a `grp-gcp-org-admins` Cloud Identity group, **Security** label, **Restricted** access type, 2-Step Verification *enforced* org-wide, granted org-level admin roles via the group (group-based, not user-direct IAM).
- **Curated API enablement.** `variables.tf` allow-lists keep only required services enabled per project (attack-surface reduction) — assertable as "no unexpected services enabled."
- **Encrypted GCS state + dedicated buckets.** `security_core/README.md` line 8 + `tstate.tf`: GCS backend for state, plus install/backup buckets — IaC-integrity + RPL signals.
- **Checkov IaC scanning in CI.** `.github/workflows/org-checkov.yml` — the build pipeline itself runs policy-as-code on the Terraform (SCR/CMT signal).

## 4. Gaps in OUR stack this could fill

Mapping each to a concrete FedPy GCP collector surface (`cloud-evidence/providers/gcp/*.ts`):

- **Assured Workloads enrollment + region.** *We almost certainly do not check this today.* No collector verifies that projects sit under an Assured Workloads folder with `FedRAMP Moderate` compliance regime and US data location. This is the GCP boundary control. **New check** → most naturally `config.ts` or `inventory.ts` (PIY-GIV / boundary), using the Assured Workloads API.
- **Organization Policy constraints.** `config.ts` is the likely home, but it is unclear we enumerate org-policy *constraints* (OS Login, disable SA-key creation, uniform bucket-level access, restrict public IP, resource-location restriction, VM external-IP deny). This is the GCP SCP analog and a core FedRAMP control. **Likely gap** → `config.ts` (CMT/governance) and `iam.ts` (for the IAM-flavored constraints).
- **VPC Service Controls (service perimeters).** RAMPpak relies on Assured Workloads + PSA + private subnets for data-exfil prevention rather than explicit VPC-SC perimeters, but **VPC Service Controls are the highest-signal GCP data-exfiltration control** and `network.ts` may not assert a perimeter exists around the projects. **Likely gap** → `network.ts` (CNA) via Access Context Manager API. (Note: RAMPpak itself does not deploy VPC-SC perimeters in the committed `.tf`, so this is an *inferred* check, not one mirrored from the repo.)
- **Per-service CMEK depth (vs Google-managed).** Our `crypto.ts` / `data.ts` likely check "encryption on." RAMPpak shows the bar is a **customer-managed Cloud KMS key per service** (Compute disks, GCS, Secret Manager, Cloud SQL). Gap → verify each resource's `kmsKeyName` is a CMEK, not the default. `crypto.ts` / `data.ts`.
- **Organization log sink + audit-log config.** `logging.ts` may check project-level logging; an *org-aggregated* sink to a CMEK destination + explicit Data-Access audit-log config (`auditConfigs`) is a stronger, org-wide assertion. Gap → `logging.ts` (MLA / CMT-LMC).
- **DNS query logging.** `logging.ts` / `network.ts` probably do not check `google_dns_policy` logging. Discrete net-new evidence. Gap → `logging.ts` / `network.ts`.
- **Cloud NAT for private egress (no external IPs on workloads).** `network.ts` checks routing/exposure; verifying instances rely on Cloud NAT (and have no external IP) is a concrete segmentation assertion. Gap → `network.ts` (CNA-RNT/ULN).
- **Shared-VPC governance + private-only managed services.** Detecting shared-VPC host/service-project structure and that managed services use Private Service Access (no public IPs) is structural and likely unchecked. Gap → `network.ts` (CNA).
- **Least-privilege / no-primitive-role service accounts.** `iam.ts` covers identity; asserting SAs avoid primitive roles (`owner`/`editor`) and hold only narrow predefined roles mirrors `bastion-iam.tf`. Strengthen `iam.ts` (IAM-ELP).
- **Curated API enablement (attack-surface reduction).** No collector likely lists enabled services per project against an expected baseline. Gap → `config.ts` / `inventory.ts` (PIY/SCR).
- **Group-based org-admin IAM + org-wide 2SV enforcement.** `iam.ts` (IAM-MFA / IAM-ELP) could assert admin access is via a Restricted security group with 2-Step Verification enforced, not user-direct bindings.
- **Security Command Center.** RAMPpak does not explicitly stand up SCC in the committed `.tf`, but SCC (Premium, with built-in detectors) is the GCP analog of AWS Security Hub/GuardDuty that the AWS RAMPpak report flagged as P0. Worth a parity check. *Inferred gap* → `config.ts` (CMT/MLA).
- **Terraform/IaC state integrity + Checkov-in-CI.** Detect the GCS state bucket is CMEK-encrypted + versioned, and that IaC policy scanning runs in the pipeline. Gap → `supplychain.ts` / `config.ts` (SCR-MON).

## 5. Integration opportunities (actionable)

Candidate **new/strengthened GCP checks** the implementer can pick up cold:

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | **Assured Workloads** enrollment: projects under an AW folder with `FedRAMP Moderate` compliance regime + `US` resource location | `config.ts` / `inventory.ts` (PIY-GIV/boundary) | `assuredworkloads.googleapis.com` `workloads.list` per folder; assert `complianceRegime == FEDRAMP_MODERATE` | idea | M | **P0** |
| 2 | **Organization Policy constraints** baseline: OS Login, disable SA-key creation, uniform bucket-level access, restrict-public-IP (SQL), VM external-IP deny, `gcp.resourceLocations` | `config.ts` (CMT) + `iam.ts` | `orgpolicy.googleapis.com` `policies.list` / `effectivePolicy`; check each constraint enforced | idea | M | **P0** |
| 3 | **VPC Service Controls** perimeter around in-scope projects (data-exfil control) | `network.ts` (CNA) | Access Context Manager `accessPolicies` → `servicePerimeters.list`; assert projects enclosed, restricted services set | idea | M | **P0** |
| 4 | **Per-service CMEK** (Compute disks, GCS, Secret Manager, Cloud SQL, BigQuery): resource encrypted with a *customer-managed* Cloud KMS key, not Google-managed | `crypto.ts`, `data.ts` | For each resource resolve `kmsKeyName`/`diskEncryptionKey`; assert it's a CMEK in expected keyring | idea | M | P1 |
| 5 | **Org aggregated log sink** + Data-Access **audit-log config** to a CMEK destination | `logging.ts` (MLA/CMT-LMC) | `logging` `sinks.list` at org scope + `getIamPolicy auditConfigs`; assert sink + DATA_READ/DATA_WRITE logging | idea | S | P1 |
| 6 | **Security Command Center** enabled (Premium tier, detectors active) — GCP parity to AWS Security Hub/GuardDuty | `config.ts` (CMT/MLA) | `securitycenter` `organizations.getSecurityCenterSettings` / sources list | idea | M | P1 |
| 7 | **Cloud NAT for private egress** + instances have **no external IP** | `network.ts` (CNA-RNT/ULN) | `compute` routers/NAT + instance `accessConfigs` empty for private tiers | idea | S | P1 |
| 8 | **Least-privilege service accounts**: no primitive roles (`owner`/`editor`), only narrow predefined roles | `iam.ts` (IAM-ELP) | `getIamPolicy` per project; flag SA bindings to primitive roles | idea | S | P1 |
| 9 | **DNS query logging** enabled on VPCs | `logging.ts` / `network.ts` | `dns` `policies.list`; assert `enableLogging == true` | idea | S | P2 |
| 10 | **Curated API enablement** vs expected baseline (attack-surface reduction) | `config.ts` / `inventory.ts` (PIY/SCR) | `serviceusage` `services.list (state=ENABLED)`; diff against allow-list | idea | S | P2 |
| 11 | **Shared-VPC + Private Service Access**: managed services (Cloud SQL) private-only; shared-VPC host/service structure present | `network.ts` (CNA) | `compute` `getXpnHost`/`xpnResources`; Cloud SQL `ipConfiguration.ipv4Enabled == false` | idea | M | P2 |
| 12 | **Group-based org-admin IAM + org-wide 2-Step Verification** enforced (Restricted security group) | `iam.ts` (IAM-MFA/IAM-ELP) | org `getIamPolicy` admin roles bound to a group, not users; Admin SDK 2SV enforcement | idea | M | P2 |
| 13 | **Terraform/IaC state integrity**: GCS state bucket CMEK-encrypted + versioned; **Checkov** IaC scan runs in CI | `supplychain.ts` / `config.ts` (SCR-MON) | detect `*-tf-state` bucket `encryption.defaultKmsKeyName` + versioning; check CI for policy-as-code | idea | M | P2 |
| 14 | Use the **module inventory (§2 table) + API allow-lists** as a GCP service-coverage checklist to confirm each FedRAMP-relevant service has a collector | docs / coverage check | cross-reference against `ksi-map` | idea | S | P2 |

**Candidate-new-checks list size: 14** (≈3 net-new P0, the rest strengthening/parity). Items 1–3 are GCP-specific and have no direct AWS-side analog in the prior report; items 4–14 mirror the AWS RAMPpak findings translated to GCP primitives.

## 6. Risks, caveats, licensing

- **License: MIT, permissive** — compatible with our Apache-2.0; we may quote config values and reuse freely with attribution. Low risk.
- **Language mismatch is total.** This is Terraform/HCL declaring desired state; FedPy is TypeScript reading actual state via `googleapis`. **Zero portable code** — value is 100% *ideas / config values*, not vendored modules. Do not attempt to "port" it.
- **Submodules not analyzed (by design).** The committed parent `.tf` is thin; the real resource detail (exact org-policy constraint list, KMS rotation period, GCS public-access/uniform-access settings, log-sink destination, VM Shielded-VM/Confidential-VM flags) lives inside the separate `github.com/Coalfire-CF/terraform-google-*` repos, which are referenced by *branch* (un-pinned, `version = n/a`). **A follow-up shallow read of `terraform-google-security-core` and `terraform-google-network`** would sharpen checks #2, #4, #5, #11. Treat §3/§4 org-policy and CMEK specifics as *inferred from the README's stated intent*, not line-verified.
- **Assured Workloads ≠ GovCloud parity.** GCP FedRAMP relies on Assured Workloads (logical controls + US-region data residency) rather than a physically separate partition. Our check (#1) must read the Assured Workloads API, not infer from region alone; and several authorized-service/region nuances change over time — assert "an approved FedRAMP regime is active," not a hardcoded service list.
- **Some values are illustrative defaults.** CIDRs (`10.0/16`, `10.1/16`, `10.2/16`), `us-east1`, `e2-standard-2`, the public-IP-on-bastion + RDP/WinRM ingress are reference defaults; the **bastion intentionally has an external IP and open RDP/SSH/WinRM to `remote_access_cidrs`** — treat the *structure* (named tiers, tag-scoped rules, CMEK disk, least-scope SA) as the signal, not the specific values. The external-IP bastion is itself something our detector might *flag*, so do not encode it as "good."
- **Version drift.** Google provider pinned `4.70.0` (older); GCP APIs and org-policy constraint names evolve. Write checks against current API surfaces, not the provider-version-era names.

## 7. Verdict

**Medium-high value as an idea source; invest a focused pass, borrow zero code.** GCP RAMPpak is the clearest "what good looks like" GCP catalog we have — a 3PAO's own prescriptive config, MIT-licensed, mapping cleanly onto our existing `gcp/*.ts` collectors. Its unique contribution over the AWS report is the **GCP-specific control trio with no AWS analog: Assured Workloads enrollment (#1), Organization Policy constraints (#2), and VPC Service Controls perimeters (#3)** — these are exactly the high-signal FedRAMP-GCP controls our `config.ts` / `network.ts` most likely under-cover today and should be the first thing we add. It yields **~14 candidate checks**, of which the single highest-value is **#1: verifying Assured Workloads (FedRAMP Moderate) enrollment**, because on GCP that *is* the compliance boundary (there is no GovCloud), closely followed by **#2 (org-policy constraint baseline)** and **#3 (VPC Service Controls)**. Use the §2 module inventory + API allow-lists as a GCP service-coverage checklist, and schedule a shallow follow-up read of `terraform-google-security-core` to line-verify the org-policy and CMEK specifics that live one layer down.
