# Research report: Coalfire-CF/Coalfire-Azure-RAMPpak

> Part of the FedPy integration-research series. Each report front-loads the
> analysis so implementation work can start without re-investigating the source.

- **Upstream:** https://github.com/Coalfire-CF/Coalfire-Azure-RAMPpak
- **Local clone:** `research/clones/Coalfire-Azure-RAMPpak` (git-ignored)
- **Language / stack:** Terraform / HCL (IaC). `hashicorp/azurerm` provider (`~> 3.45`–`3.61`) + `hashicorp/azuread` (`2.35.0`), Terraform `~> 1.5.0`. Azure **Government** targeted (`usgovvirginia` primary, `usgovtexas` DR; `environment = "usgovernment"`).
- **License:** **MIT** (`License.md`, Copyright 2023 Coalfire Systems Inc.; README badge 2024). Permissive — compatible with our Apache-2.0; we may quote config values / reuse text freely with attribution. But see §6: it is Terraform, not portable TS.
- **Activity / maturity:** Small parent repo (~95 files, 1.0 MB, shallow clone). Last commit `2026-04-08` (PR #15, region-setup update). Stable Coalfire OpenSource reference architecture; composes versioned `terraform-azurerm-<service>` and `ACE-Azure-*` modules (pinned tags like `ACE-Azure-SecurityCore?ref=v1.0.2`, `ACE-Azure-RegionSetup?ref=v1.0.7`; service modules pulled at HEAD).
- **One-line:** A staged "security-core → region-setup → networking → mgmt tooling" parent Terraform repo that composes Coalfire's `terraform-azurerm-<service>` modules to stand up a **FedRAMP Moderate Azure Government** landing zone — i.e. a 3PAO's declaration of *what a compliant Azure environment should look like*.

## 1. What it does

RAMPpak (Azure) is the **prescriptive counterpart to FedPy's detective role**, mirroring the AWS RAMPpak (report 02) but for Azure Government. Where FedPy *reads* live cloud config and judges it against the 63 KSIs, RAMPpak *declares* the target state: a hardened management plane with a central Log Analytics workspace + Microsoft Sentinel, Key Vaults for CMKs, segmented VNets behind Azure Firewall, Recovery Services backup, STIG-hardened bastions, and Azure AD/RBAC bootstrapping — all in `usgovernment` cloud.

The parent repo contains almost no resources itself — it is an **orchestration layer** that wires separately-versioned Coalfire modules together, passing outputs between stages via **Azure Storage remote state** (`tstate.tf` / `remote-data.tf` per folder). It is organized as a **staged deployment** under `terraform/prod/us-va/` with an explicit deploy order (README §"Deployment Order of Operations"): `security-core` → `region-setup` → `mgmt/mgmt-network` → `app/app-network` → `mgmt/vnet-peering` → `mgmt/key-vault` → `mgmt/azure-automation` → `mgmt/bastion` → `mgmt/backup` → `mgmt/sentinel`. A DR region (`us-tx`) is referenced in the README but not committed in this snapshot.

The audience is FedRAMP CSPs / 3PAOs building an Azure Government boundary. **Crucially for us, FedPy has NO Azure collector today** (AWS + GCP only; Azure is the GAP-ANALYSIS §4.4 out-of-scope gap). So this report's primary job is not "borrow a few checks" — it is to serve as the **requirements spec for a future `cloud-evidence/providers/azure/*.ts` collector set**: the Azure services Coalfire deems FedRAMP-relevant, the hardening they enforce, and how each maps onto our existing KSI domains.

## 2. Architecture & key components

Top-level layout (real paths from the clone):

- `README.md` — deploy order, MIT license, repo map, AzureUSGovernment cloud-set instructions, admin-onboarding (PIP/VPN CIDR) flow.
- `terraform/prod/global-vars.tf` — global defaults: `az_environment = "usgovernment"`, `azure_cloud = "AzureUSGovernment"`, `function = "mp"` (management plane), `vm_admin_username = "xadm"`, plus `cidrs_for_remote_access` / `ip_for_remote_access` (admin allowlist) and `admin_principal_ids` (Azure AD object GUIDs).
- `terraform/prod/us-va/regional-vars.tf` — `location = "usgovvirginia"`, `location_dr = "usgovtexas"`, `mgmt_network_cidr = 10.10.0.0/16`, `app_network_cidr = 10.20.0.0/16`, AZ validators (1/2/3), the `azurerm` provider block with `environment = var.az_environment`.
- `terraform/prod/us-va/security-core/core.tf` — composes `ACE-Azure-SecurityCore?ref=v1.0.2`: core RG, **primary Log Analytics workspace**, Key Vault for CMKs, Terraform-state storage account, subscription diagnostic logs, admin IAM bootstrap, and a set of **private DNS zones** for `*.usgovcloudapi.net` private-link (blob/table/queue/file/postgres) + `privatelink.azurecr.us`.
- `terraform/prod/us-va/region-setup/setup.tf` — composes `ACE-Azure-RegionSetup?ref=v1.0.7`: mgmt/app/keyvault/networking/identity RGs, **Network Watcher**, storage accounts (Recovery Services, Cloud Shell, **NSG flow logs**, installs, VM diag, FedRAMP docs), Azure Compute Gallery + STIG golden-image definitions, and an (optional) Azure Firewall hook (`firewall_vnet_subnet_ids`).
- `mgmt/mgmt-network/mgmt.tf` + `app/app-network/app.tf` — compose `terraform-azurerm-vnet`: management VNet with **9 segmented subnets** (public, iam, cicd, secops, siem, monitor, bastion, `AzureFirewallSubnet`, private-endpoint `pe`, `psql`) and app VNet with dmz/edge/backend tiers. Subnets carry **service endpoints** (KeyVault/Storage/Sql/ContainerRegistry) and private-link policies; VNets attach to private DNS + Log Analytics diagnostics.
- `mgmt/vnet-peering/vnet-peering.tf` — bidirectional mgmt↔app `azurerm_virtual_network_peering`.
- `mgmt/key-vault/` — composes `terraform-azurerm-key-vault` twice (`ad-kv` for AD service-account secrets, `certs-kv` for certs). Both set `network_acls { default_action = "Deny", bypass = "AzureServices" }` locked to VNet subnets + admin CIDRs, and stream diagnostics to Log Analytics. `admin-kv-roles.tf` assigns **RBAC** roles (Key Vault Secrets Officer / Certificates Officer / RG Owner) per `admin_principal_ids`.
- `mgmt/sentinel/sentinel.tf` — composes `terraform-azurerm-sentinel` onto the core Log Analytics workspace (SIEM).
- `mgmt/azure-automation/` — `terraform-azurerm-automation-account` (patching/runbooks) + `aad_permissions.tf` granting the automation account's managed identity `Virtual Machine Contributor` across subscriptions.
- `mgmt/backup/backupConfig.tf` — `azurerm_recovery_services_vault` + `azurerm_backup_policy_vm` (Daily 02:00 UTC; 14 daily / 4 weekly / 3 monthly retention) + diagnostics.
- `mgmt/bastion/` — `terraform-azurerm-vm-windows` from a **CIS STIG marketplace image** (`cis-win-2019-stig`) + `nsg.tf` (`terraform-azurerm-nsg`) allowing RDP only from `cidrs_for_remote_access`, with **NSG flow logs** to the flow-logs storage account + Log Analytics.
- `shellscripts/{linux,windows}/*Diagnostics.json` — Azure Monitor agent diagnostic config (perf counters + event logs to collect).
- `.github/workflows/` — org CI: **Checkov** IaC scan, terraform fmt/validate/docs, md-lint, release.

**Module inventory (the `terraform-azurerm-<service>` / `ACE-Azure-*` coverage map)** — these double as the FedRAMP-relevant Azure service list a future Azure collector must cover:

| Module | Stage | What it stands up | KSI domain(s) |
|--------|-------|-------------------|---------------|
| `ACE-Azure-SecurityCore` (`v1.0.2`) | security-core | Log Analytics workspace, CMK Key Vault, TF-state storage, subscription diag logs, admin IAM, private DNS zones | MLA, CMT, IAM, SVC |
| `ACE-Azure-RegionSetup` (`v1.0.7`) | region-setup | RGs, Network Watcher, flow-log/diag/installs/docs storage, Compute Gallery + STIG images, Azure Firewall hook | CNA, MLA, PIY, RPL |
| `terraform-azurerm-vnet` | networking | VNets, segmented subnets, service endpoints, private DNS attach, diag | CNA |
| `terraform-azurerm-nsg` | bastion/net | NSGs + custom rules + NSG **flow logs** | CNA, MLA |
| `terraform-azurerm-key-vault` | key-vault | Key Vaults w/ deny-by-default ACLs, RBAC, diag | SVC, IAM, MLA |
| `terraform-azurerm-sentinel` | sentinel | Microsoft Sentinel (SIEM) on Log Analytics | MLA, INR |
| `terraform-azurerm-automation-account` | automation | Automation Account + managed identity (patching/runbooks) | CMT, SVC |
| `terraform-azurerm-vm-windows` | bastion | CIS-STIG Windows VM, KV-integrated | CNA, CMT, SCR |
| `terraform-azurerm-diagnostics` | backup/etc | Resource → Log Analytics diagnostic settings wiring | MLA |
| `azurerm_recovery_services_vault` / `_backup_policy_vm` (inline) | backup | Backup vault + VM backup policy/retention | RPL |

Data formats: pure HCL `.tf`/`.tfvars`; Azure Storage backend state; no OSCAL, no JSON evidence. Nothing portable to our TS detective directly — the value is the **service + setting inventory** and the **defensible config values**.

## 3. What's genuinely interesting for FedPy

The signal is a set of **concrete, 3PAO-blessed Azure config values** that map to detective pass/fail assertions — and, more importantly, the **shape of an Azure boundary** we have never modeled:

- **Azure Government as the compliance baseline.** Everything is `environment = "usgovernment"`, `location = usgovvirginia`/`usgovtexas`, private DNS zones on `*.usgovcloudapi.net` / `azurecr.us`. A FedRAMP-relevant Azure check should assert resources live in a Gov region and (for High) a Gov cloud — analogous to our AWS GovCloud-partition awareness.
- **Central Log Analytics workspace + Microsoft Sentinel = the MLA/INR backbone.** `security-core` stands up the workspace; `sentinel.tf` layers Sentinel on it; nearly every module wires `diag_log_analytics_id` diagnostic settings into it (`terraform-azurerm-diagnostics`). The detective bar: a workspace exists, Sentinel is enabled on it, and key resource types ship diagnostic settings there.
- **Subscription-level diagnostic/activity logs.** `security-core` README enumerates the categories: `Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth`. Assertable as "subscription activity-log export to the central workspace, all categories."
- **Key Vault with deny-by-default network ACLs + RBAC authorization.** `key-vault/ad-kv.tf` sets `network_acls { default_action = "Deny"; bypass = "AzureServices" }` scoped to VNet subnets + admin CIDRs, and `admin-kv-roles.tf` uses **RBAC role assignments** (Secrets/Certs Officer) rather than legacy access policies. Strong SVC/IAM signal: vaults are private + RBAC-governed.
- **CMK story via the core Key Vault.** `security-core` provisions "Key Vault for CMK's." The FedRAMP bar is customer-managed keys, not platform-managed — a future check resolves each encryptable resource's key source to a Key Vault key.
- **Network segmentation as structure.** Mgmt VNet carves **named functional subnets** (iam/cicd/secops/siem/monitor/bastion/pe/psql) + a dedicated `AzureFirewallSubnet`; app VNet has dmz/edge/backend tiers; mgmt↔app traffic only via explicit peering. Private-endpoint (`pe`) + `psql` subnets enforce `enforce_private_link_endpoint_network_policies = true`. A structural "dedicated firewall subnet + tiered segmentation + private endpoints" check.
- **NSG flow logs → storage + Network Watcher.** `bastion/nsg.tf` wires `network_watcher_flow_log` + `storage_account_flowlogs_id` + Log Analytics. Both *existence* and *destination* are assertable (CNA + MLA).
- **Least-exposure bastion.** RDP (3389) allowed **only** from `cidrs_for_remote_access`; no `0.0.0.0/0`. The "no broad inbound management ports" check.
- **STIG-hardened golden images.** Bastion launches from `center-for-internet-security-inc / cis-win-2019-stig`; region-setup bootstraps Compute Gallery image definitions (RHEL-8 STIG, Win-2022). The "VM launched from an approved/hardened image" provenance check (novel for us, SCR/CMT).
- **Recovery Services backup with explicit retention.** `backupConfig.tf`: Daily 02:00 UTC, 14 daily / 4 weekly / 3 monthly. Assertable retention values for RPL.
- **Admin identity governed by Azure AD object GUIDs + IP allowlists.** `admin_principal_ids` (AAD object IDs) drive every RBAC assignment; admin onboarding requires adding a PIP/VPN CIDR. Maps to IAM (principals, least privilege, conditional access).
- **Encrypted, remote Terraform state per stage.** Every `tstate.tf` uses an `azurerm` backend in a Gov storage account — an IaC-integrity signal (SCR).
- **Checkov in CI.** `.github/workflows/org-checkov.yml` runs Checkov on every `**.tf` PR — confirms the desired-state itself is policy-scanned (a posture-as-code pattern worth noting for our SCR/SCG story).

## 4. Gaps in OUR stack this could fill

The headline gap is total: **there is no `cloud-evidence/providers/azure/` directory today.** This repo is the most concrete available enumeration of *which* Azure surfaces a FedRAMP collector must read. Mapping the prescriptive content onto a **proposed Azure collector module plan** (parallel to our existing AWS/GCP per-domain files):

| Proposed file | KSI domain(s) | Azure resources / settings to check | Azure JS SDK area |
|---------------|---------------|--------------------------------------|-------------------|
| `azure/iam.ts` | IAM | Azure AD users/MFA/conditional-access, **PIM** eligible-vs-active role assignments (JIT), RBAC role assignments + custom roles (least privilege), service principals / managed identities, guest/stale accounts | `@microsoft/microsoft-graph-client` (AAD/PIM/CA) + `@azure/arm-authorization` (RBAC) |
| `azure/network.ts` | CNA, SVC | NSGs + rules (no broad inbound mgmt ports), Azure Firewall + dedicated `AzureFirewallSubnet`, VNet peering topology, subnet segmentation/service endpoints, **private endpoints**, public-IP exposure | `@azure/arm-network` |
| `azure/logging.ts` | MLA, CMT, INR | Log Analytics workspace existence + retention, **diagnostic settings** per resource → workspace, subscription activity-log export (all categories), **NSG flow logs**, **Microsoft Sentinel** enabled on the workspace | `@azure/arm-monitor`, `@azure/arm-operationalinsights`, `@azure/arm-securityinsight` (Sentinel) |
| `azure/crypto.ts` / `secrets.ts` | SVC, IAM | Key Vault deny-by-default network ACLs, RBAC-authorization mode, soft-delete/purge-protection, **CMK** key source on encryptable resources, secret/cert rotation, diagnostics on vaults | `@azure/arm-keyvault` |
| `azure/config.ts` | CMT, SCR, SVC | **Microsoft Defender for Cloud** plan tiers + secure score, **Azure Policy** assignments/compliance (esp. a FedRAMP/NIST initiative), resource-level encryption-at-rest, storage-account `Deny` public access + HTTPS-only | `@azure/arm-security` (Defender), `@azure/arm-policyinsights` + `@azure/arm-resources` (Policy), `@azure/arm-storage` |
| `azure/data.ts` | SVC | Storage/SQL/PostgreSQL encryption (CMK), TLS-min-version, private-endpoint-only access, public-network-access disabled | `@azure/arm-storage`, `@azure/arm-sql`, `@azure/arm-postgresql` |
| `azure/backup.ts` | RPL | Recovery Services vault presence, VM backup policy + **retention** (daily/weekly/monthly), protected-item coverage | `@azure/arm-recoveryservices(-backup)` |
| `azure/inventory.ts` | PIY | Resource inventory across subscriptions/RGs, VM image provenance (approved/STIG gallery image), tagging compliance | `@azure/arm-resources`, `@azure/arm-compute` |
| `azure/supplychain.ts` | SCR, CMT | Azure Container Registry + image scanning (Defender for Containers), Automation Account patch/update-management posture | `@azure/arm-containerregistry`, `@azure/arm-automation` |

Specific net-new coverage this repo proves we'd want:
- **PIM eligible-vs-active assignments** (true JIT) — Azure has a first-class PIM API; richer than what AWS/GCP offer for IAM-JIT.
- **Defender for Cloud plan tiers + secure score** — no AWS/GCP equivalent in our stack; a single high-signal CMT/SCR check.
- **Azure Policy compliance against a FedRAMP/NIST initiative** — Azure ships built-in FedRAMP Moderate/High policy initiatives; querying compliance state is a uniquely strong governance evidence source (CMT).
- **Sentinel-enabled-on-workspace** — concrete MLA/INR SIEM check.
- **Diagnostic-settings-present-per-resource** — the Azure idiom for "logging on," which differs structurally from AWS CloudTrail/GCP audit logs and must be modeled explicitly.

## 5. Integration opportunities (actionable)

For each, a row the implementer can pick up cold. Note: unlike reports 01/02, the dominant opportunity here is **building net-new Azure collectors** (effort L), not borrowing single checks.

| # | Opportunity | FedPy target | Approach | Borrow code or just the idea? | Effort | Priority |
|---|-------------|--------------|----------|-------------------------------|--------|----------|
| 1 | **Stand up the Azure provider scaffold + read-only auth** (DefaultAzureCredential / service-principal, subscription enumeration) so any `azure/*.ts` can run | new `cloud-evidence/providers/azure/`, `core/azure-auth.ts` | `@azure/identity` `DefaultAzureCredential`; `@azure/arm-subscriptions` to list subs; mirror AWS/GCP auth bootstrap | idea (new code) | M | P0 |
| 2 | **Read-only guardrail parity** for the Azure SDK (only allow `get/list` ops) | `core/readonly-guard` (Proxy) | Wrap `@azure/arm-*` clients in the same Proxy pattern used for AWS/GCP (C.3); allow only `get*`/`list*`/`check*` methods | port pattern | M | P0 |
| 3 | **`azure/logging.ts`** — Log Analytics + diagnostic settings + activity-log + Sentinel + NSG flow logs (MLA/CMT/INR) | new collector | `@azure/arm-operationalinsights`, `@azure/arm-monitor` (diagnosticSettings), `@azure/arm-securityinsight` | idea | L | P0 |
| 4 | **`azure/iam.ts`** — AAD MFA/CA, **PIM** JIT, RBAC least-privilege, service principals (IAM) | new collector | `@microsoft/microsoft-graph-client` + `@azure/arm-authorization` | idea | L | P0 |
| 5 | **`azure/config.ts`** — **Defender for Cloud** tiers + secure score, **Azure Policy** FedRAMP-initiative compliance, storage public-access/HTTPS (CMT/SCR/SVC) | new collector | `@azure/arm-security`, `@azure/arm-policyinsights` | idea | L | P0 |
| 6 | **`azure/network.ts`** — NSG rules (no broad mgmt inbound), Azure Firewall + dedicated subnet, peering, private endpoints, public exposure (CNA/SVC) | new collector | `@azure/arm-network` | idea | L | P1 |
| 7 | **`azure/crypto.ts` / `secrets.ts`** — Key Vault deny-by-default ACLs, RBAC mode, purge-protection, **CMK** key source (SVC/IAM) | new collector | `@azure/arm-keyvault` | idea | M | P1 |
| 8 | **`azure/data.ts`** — Storage/SQL/PostgreSQL CMK + TLS-min + private-only (SVC) | new collector | `@azure/arm-storage`, `@azure/arm-sql`, `@azure/arm-postgresql` | idea | M | P1 |
| 9 | **`azure/backup.ts`** — Recovery Services vault + VM backup policy/retention coverage (RPL) | new collector | `@azure/arm-recoveryservices` | idea | M | P1 |
| 10 | **`azure/inventory.ts`** — cross-subscription resource inventory + **approved/STIG image provenance** for VMs (PIY/SCR) | new collector | `@azure/arm-resources`, `@azure/arm-compute` | idea | M | P2 |
| 11 | **`azure/supplychain.ts`** — ACR image scanning (Defender for Containers) + Automation Account patch posture (SCR/CMT) | new collector | `@azure/arm-containerregistry`, `@azure/arm-automation` | idea | M | P2 |
| 12 | Use the **§2 module-inventory table** + this repo's deploy order as the **Azure coverage checklist** and KSI-map registration plan | docs / coverage check / `ksi-map` | cross-reference each proposed `azure/*.ts` against the 63 KSIs, same as AWS/GCP | idea | S | P1 |
| 13 | **Gov-region / Gov-cloud awareness**: assert resources live in `usgov*` regions / `usgovernment` cloud (partition-agnostic like our AWS GovCloud handling) | `core/azure-auth.ts` + collectors | read `environment` / `location`; don't hardcode commercial endpoints | idea | S | P1 |

## 6. Risks, caveats, licensing

- **License: MIT, permissive** — compatible with our Apache-2.0; we can quote config values and reuse text freely with attribution. Low risk. (Same as AWS RAMPpak.)
- **Language mismatch is total.** This is Terraform/HCL declaring desired state; FedPy is TypeScript reading actual state. **Zero portable code** — value is 100% *ideas / service inventory / config values*, not vendored modules. Do not attempt to "port" it.
- **This is a net-new provider, not an extension.** Unlike AWS/GCP work, items #3–#11 each create a brand-new collector with no existing Azure scaffolding to lean on. Realistic effort is **L per domain**; #1/#2 (auth + read-only guard) are prerequisites that gate everything else. Budget accordingly — this is the largest single expansion in the research series.
- **Azure read-only SDK story is solid (TS path exists).** Microsoft ships first-party JS/TS SDKs: `@azure/identity` (`DefaultAzureCredential`, service principal, managed identity, Azure CLI cred) for auth, and per-service management-plane clients `@azure/arm-*` (network, monitor, keyvault, security, authorization, recoveryservices, storage, sql, policyinsights, resources, compute, containerregistry, automation, operationalinsights, securityinsight). AAD/PIM live behind Microsoft Graph (`@microsoft/microsoft-graph-client`), which is a *different* auth surface than ARM and adds onboarding complexity (Graph API permissions consent). All are `get*`/`list*`-friendly, so the read-only Proxy guardrail transfers cleanly.
- **Read-only guardrail implication:** the collector's service principal needs only the **`Reader`** RBAC role at subscription scope plus a few data-plane reads (e.g. **`Key Vault Reader`**) and **Graph directory-read** scopes (`Directory.Read.All`, `RoleManagement.Read.Directory` for PIM). No write/contributor role — enforce both via least-privilege role assignment *and* the SDK Proxy guard (defense in depth). Defender/Policy/Sentinel reads are covered by `Reader` + `Security Reader`.
- **GovCloud-specific defaults.** Region `usgovvirginia`/`usgovtexas`, cloud `usgovernment`, endpoints on `*.usgovcloudapi.net` / `azurecr.us`. The Azure SDK selects endpoints per-cloud via `@azure/identity` authority host / `AzureAuthorityHosts.AzureGovernment` — collectors must be cloud-agnostic (commercial + Gov), not hardcode Gov endpoints.
- **Submodules not analyzed.** The real resource detail lives in the separate `terraform-azurerm-*` and `ACE-Azure-*` repos (not cloned per instructions). The parent repo + READMEs give the service inventory and key values, but exact hardening (e.g., Key Vault soft-delete/purge-protection flags, storage public-access-block, VM disk-encryption specifics, Sentinel data connectors) lives one layer down — a follow-up read of `terraform-azurerm-key-vault`, `-vnet`, and `ACE-Azure-SecurityCore` would sharpen checks #3, #6, #7.
- **Impact level = Moderate, single profile.** `security-core/README.md` states "FedRAMP Moderate." Unlike the AWS repo's per-stage `High`/`Moderate` tags, this repo does not carry explicit per-module impact-level annotations, so it is a weaker source for High-vs-Moderate threshold differences. Our Azure checks should still parameterize by impact level (as our AWS/GCP collectors do).
- **Some values are illustrative placeholders.** `admin_principal_ids` / `subscription_id` / `cidrs_for_remote_access` default to `0000…`/`127.0.0.x` examples, and the SAS dates in `region-setup` are literal sample dates. Treat *structure* as the signal, not the placeholder values.

## 7. Verdict

**High strategic value as the requirements spec for FedPy's missing Azure provider; invest a dedicated multi-collector build, borrow zero code.** This repo is the clearest available map of *what a FedRAMP-compliant Azure Government boundary looks like* from a top 3PAO, and it lands squarely on our biggest known gap (no Azure collector, GAP-ANALYSIS §4.4). It does not yield a handful of incremental checks like the AWS/GCP work — it yields a **whole provider plan**: ~9 `azure/*.ts` collectors plus auth + read-only-guard scaffolding, mapped onto our existing IAM/CNA/MLA/CMT/SVC/RPL/PIY/SCR/INR domains. An Azure collector is **realistic**: the TS SDK path is first-party and read-only-friendly (`@azure/identity` + `@azure/arm-*`, with Graph for AAD/PIM), the read-only Proxy guardrail transfers, and a `Reader`-scoped service principal is sufficient. The single highest-value starting point is **#1+#2 (Azure auth + read-only guard scaffold)** — the gate for everything — immediately followed by **#3 (`azure/logging.ts`: Log Analytics + diagnostic settings + Sentinel)** and **#5 (`azure/config.ts`: Defender for Cloud + Azure Policy FedRAMP-initiative compliance)**, the two checks with the strongest, most Azure-native compliance signal and no AWS/GCP equivalent in our stack. A worthwhile follow-up is a shallow read of `terraform-azurerm-key-vault` and `ACE-Azure-SecurityCore` to extract the soft-delete/CMK/diagnostic specifics one layer down.
