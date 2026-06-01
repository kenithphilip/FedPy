/**
 * Azure FedRAMP reference-architecture audit (AZ-CHK).
 *
 * Checks a running Azure environment against the hardening a FedRAMP-compliant
 * build is expected to have. Derived **clean-room** from the Coalfire Azure RAMPpak
 * reference architecture (research report 03 — idea source, MIT, no code copied).
 * Emitted as its own `AUDIT-REFARCH-AZURE.json` evidence file so the findings
 * flow into the NIST 800-53 benchmark, OSCAL, the crosswalk, and the signed
 * manifest — alongside the existing AWS-CHK / GCP-CHK audits.
 *
 * Every check uses **Azure Resource Graph** (already authenticated via the AZ-1
 * scaffolding) — one client, no extra SDK deps. Read-only via the Azure Proxy
 * guardrail. Each check degrades to a warning, never a false failure, when its
 * data is unavailable (RBAC gap, table not enabled, etc.).
 */
import * as azure from '../../core/auth/azure.ts';
import type { EvidenceFile, Finding, ProviderBlock, RawEvidence } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

export interface AzRefArchCtx { runId: string; frmrVersion: string; }

/** Run one KQL query across the given subscriptions and return all rows (paginated). */
async function runKql(client: any, subscriptions: string[], query: string): Promise<any[]> {
  const out: any[] = [];
  let skipToken: string | undefined;
  let pages = 0;
  do {
    const r = await client.resources({
      subscriptions, query,
      options: { top: 1000, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
    });
    const data = Array.isArray(r?.data) ? r.data : [];
    out.push(...data);
    skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
  } while (skipToken && ++pages < 50);
  return out;
}

export async function collectAzureReferenceArch(subscriptions: string[], ctx: AzRefArchCtx): Promise<EvidenceFile> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];

  if (subscriptions.length === 0) {
    warnings.push('Azure reference-arch: no subscriptions configured in config.azure.subscriptions.');
  }

  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { warnings.push(`Azure Resource Graph client construction failed: ${e?.message ?? e}`); }

  // Helper to gate a check on client availability + subscriptions, capturing a warning otherwise.
  async function check<T>(label: string, fn: () => Promise<T>): Promise<T | undefined> {
    if (!client || subscriptions.length === 0) { warnings.push(`${label} skipped: ${!client ? 'no Resource Graph client' : 'no subscriptions configured'}.`); return undefined; }
    try { return await fn(); } catch (e: any) { warnings.push(`${label}: ${e?.message ?? e}`); return undefined; }
  }

  // ── 1) Defender for Cloud — at least one paid pricing tier per subscription ──
  await check('Defender for Cloud (securityresources pricings)', async () => {
    const rows = await runKql(client, subscriptions,
      'securityresources | where type == "microsoft.security/pricings" ' +
      '| extend tier = tostring(properties.pricingTier) ' +
      '| summarize standardPlans = countif(tier == "Standard"), totalPlans = count() by subscriptionId');
    const subsWithStandard = rows.filter((r) => Number(r.standardPlans) > 0).length;
    evidence.push(ev('securityresources.pricings', { subscriptions: subscriptions.length, with_standard_plan: subsWithStandard, raw: rows.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.defender.enabled', passed: subsWithStandard > 0, severity: 'high',
      current: { summary: `${subsWithStandard}/${subscriptions.length} subscription(s) have ≥1 Defender plan on Standard tier.`, observations: { subsWithStandard, total: subscriptions.length } },
      target: { summary: 'Microsoft Defender for Cloud is on the Standard tier for in-scope services (Servers / SQL / Storage / App Service / Containers / Key Vault).', rationale: 'NIST CA-7, RA-5, SI-4. Continuous control monitoring + threat detection.' },
      gap: { description: 'No Defender for Cloud plan is on the Standard tier in any subscription.', affected_resources: [{ type: 'azure_security_pricing', identifier: subscriptions.join(','), attributes: {} }] },
      remediation: { summary: 'Enable Defender for Cloud Standard plans on Servers, Storage, SQL, App Service, Containers, Key Vault for in-scope subscriptions.', options: [{ approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az account set --subscription <sub>', 'az security pricing create -n VirtualMachines --tier Standard', 'az security pricing create -n StorageAccounts --tier Standard', 'az security pricing create -n SqlServers --tier Standard'] }] },
      nist_controls: ['ca-7', 'ra-5', 'si-4'],
    }));
  });

  // ── 2) FedRAMP Policy Initiative assigned ──
  await check('Azure Policy initiative (policyresources)', async () => {
    const rows = await runKql(client, subscriptions,
      'policyresources | where type =~ "microsoft.authorization/policyassignments" ' +
      '| extend dn = tostring(properties.displayName), pd = tostring(properties.policyDefinitionId) ' +
      '| where dn contains_cs "FedRAMP" or pd contains_cs "FedRAMP" ' +
      '| project subscriptionId, name, displayName=dn, policyDefinitionId=pd');
    const assignments = rows.length;
    evidence.push(ev('policyresources.fedramp_assignments', { count: assignments, sample: rows.slice(0, 10) }));
    findings.push(finding({
      rule: 'azure.policy.fedramp_initiative', passed: assignments > 0, severity: 'medium',
      current: { summary: `${assignments} FedRAMP-related policy assignment(s) found.`, observations: { count: assignments } },
      target: { summary: 'The FedRAMP Moderate / High built-in policy initiative is assigned at the management-group or subscription scope.', rationale: 'NIST CA-2, CM-6. Preventive + auditable compliance guardrails.' },
      gap: { description: 'No FedRAMP policy initiative assigned in this tenancy.', affected_resources: [{ type: 'azure_policy_assignment', identifier: 'fedramp', attributes: {} }] },
      remediation: { summary: 'Assign the FedRAMP Moderate (or High) built-in initiative at the management-group scope.', options: [{ approach: 'Azure Portal → Policy → Definitions → built-in → search "FedRAMP" → Assign.', mechanism: 'console', steps: ['Pick the right tier initiative (Moderate or High)', 'Assign at MG scope', 'Enable compliance auto-evaluation'] }] },
      nist_controls: ['ca-2', 'cm-6'],
    }));
  });

  // ── 3) Storage accounts must not allow blob public access ──
  await check('Storage public-blob access (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
      '| extend pb = tobool(properties.allowBlobPublicAccess) ' +
      '| project subscriptionId, name, id, pb');
    const total = rows.length;
    const offenders = rows.filter((r) => r.pb === true);
    evidence.push(ev('storage.allowBlobPublicAccess', { total, offenders: offenders.length, sample_offenders: offenders.slice(0, 20).map((r) => r.id) }));
    findings.push(finding({
      rule: 'azure.storage.no_public_blob', passed: total === 0 || offenders.length === 0, severity: 'high',
      current: { summary: `${offenders.length}/${total} storage account(s) allow blob public access.`, observations: { offenders: offenders.slice(0, 50).map((r) => r.id) } },
      target: { summary: 'Every storage account has `allowBlobPublicAccess = false`.', rationale: 'NIST AC-3, AC-6, SC-7. Eliminates anonymous blob exposure.' },
      gap: { description: 'One or more storage accounts allow anonymous blob access.', affected_resources: offenders.slice(0, 50).map((r: any) => ({ type: 'azure_storage_account', identifier: r.id, attributes: {} })) },
      remediation: { summary: 'Set allowBlobPublicAccess=false on every storage account.', options: [{ approach: 'Terraform / Bicep: allow_blob_public_access = false.', mechanism: 'terraform', steps: ['Set allow_blob_public_access = false on all azurerm_storage_account', 'Enforce org-wide via the built-in policy "Storage accounts should prevent public blob access"'] }] },
      nist_controls: ['ac-3', 'ac-6', 'sc-7'],
    }));
  });

  // ── 4) Storage accounts must enforce HTTPS + TLS ≥ 1.2 ──
  await check('Storage HTTPS-only + TLS ≥ 1.2 (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
      '| extend https = tobool(properties.supportsHttpsTrafficOnly), tls = tostring(properties.minimumTlsVersion) ' +
      '| project subscriptionId, name, id, https, tls');
    const total = rows.length;
    const offenders = rows.filter((r) => r.https !== true || !['TLS1_2', 'TLS1_3'].includes(String(r.tls)));
    evidence.push(ev('storage.https_tls', { total, offenders: offenders.length, sample_offenders: offenders.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.storage.https_only', passed: total === 0 || offenders.length === 0, severity: 'high',
      current: { summary: `${offenders.length}/${total} storage account(s) violate HTTPS-only + TLS 1.2+.`, observations: { offenders: offenders.slice(0, 50) } },
      target: { summary: '`supportsHttpsTrafficOnly = true` AND `minimumTlsVersion` is `TLS1_2` (or `TLS1_3`) on every storage account.', rationale: 'NIST SC-8, SC-8(1), SC-13. Strong transport encryption.' },
      gap: { description: 'Storage accounts allow HTTP or weak TLS versions.', affected_resources: offenders.slice(0, 50).map((r: any) => ({ type: 'azure_storage_account', identifier: r.id, attributes: { https: r.https, tls: r.tls } })) },
      remediation: { summary: 'Enforce HTTPS-only + TLS 1.2 minimum on every account.', options: [{ approach: 'Terraform / Bicep: enable_https_traffic_only + min_tls_version.', mechanism: 'terraform', steps: ['Set enable_https_traffic_only = true', 'Set min_tls_version = "TLS1_2"', 'Enforce via built-in policy "Secure transfer to storage accounts should be enabled"'] }] },
      nist_controls: ['sc-8', 'sc-8.1', 'sc-13'],
    }));
  });

  // ── 5) Storage account public-network-access should be restricted ──
  await check('Storage public-network-access (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
      '| extend pna = tostring(properties.publicNetworkAccess), defAct = tostring(properties.networkAcls.defaultAction) ' +
      '| project subscriptionId, name, id, pna, defAct');
    const total = rows.length;
    const offenders = rows.filter((r) => (r.pna ?? '').toLowerCase() !== 'disabled' && (r.defAct ?? '').toLowerCase() !== 'deny');
    evidence.push(ev('storage.publicNetworkAccess', { total, offenders: offenders.length, sample: offenders.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.storage.network_restricted', passed: total === 0 || offenders.length === 0, severity: 'medium',
      current: { summary: `${offenders.length}/${total} storage account(s) accept traffic from any network.`, observations: { offenders: offenders.slice(0, 50) } },
      target: { summary: '`publicNetworkAccess = Disabled` (or `networkAcls.defaultAction = Deny` with explicit allow-list) on every storage account.', rationale: 'NIST SC-7, AC-4.' },
      gap: { description: 'One or more storage accounts are reachable from any IP.', affected_resources: offenders.slice(0, 50).map((r: any) => ({ type: 'azure_storage_account', identifier: r.id, attributes: { publicNetworkAccess: r.pna, defaultAction: r.defAct } })) },
      remediation: { summary: 'Disable public network access OR restrict via the storage-account firewall + Private Endpoints.', options: [{ approach: 'Terraform: network_rules { default_action = "Deny" }.', mechanism: 'terraform', steps: ['Set public_network_access_enabled = false', 'OR network_rules.default_action = "Deny" + allow-list', 'Provision Private Endpoints for in-VNet access'] }] },
      nist_controls: ['sc-7', 'ac-4'],
    }));
  });

  // ── 6) Key Vault: soft-delete + purge protection + RBAC mode ──
  await check('Key Vault hardening (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.keyvault/vaults" ' +
      '| extend sd = tobool(properties.enableSoftDelete), pp = tobool(properties.enablePurgeProtection), rbac = tobool(properties.enableRbacAuthorization) ' +
      '| project subscriptionId, name, id, sd, pp, rbac');
    const total = rows.length;
    const offenders = rows.filter((r) => r.sd !== true || r.pp !== true || r.rbac !== true);
    evidence.push(ev('keyvault.hardening', { total, offenders: offenders.length, sample: offenders.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.keyvault.soft_delete_purge_rbac', passed: total === 0 || offenders.length === 0, severity: 'high',
      current: { summary: `${offenders.length}/${total} Key Vault(s) lack soft-delete + purge-protection + RBAC.`, observations: { offenders: offenders.slice(0, 50) } },
      target: { summary: 'Every Key Vault has soft-delete + purge-protection + RBAC authorization (not legacy access policies).', rationale: 'NIST SC-12, SC-13, SC-28, AC-3.' },
      gap: { description: 'Key Vaults have soft-delete / purge-protection / RBAC mode disabled.', affected_resources: offenders.slice(0, 50).map((r: any) => ({ type: 'azure_keyvault', identifier: r.id, attributes: { soft_delete: r.sd, purge_protection: r.pp, rbac: r.rbac } })) },
      remediation: { summary: 'Set enable_soft_delete + enable_purge_protection + enable_rbac_authorization = true on every vault.', options: [{ approach: 'Terraform / Bicep.', mechanism: 'terraform', steps: ['enable_soft_delete = true', 'enable_purge_protection = true', 'enable_rbac_authorization = true', 'Migrate access policies to Azure RBAC role assignments'] }] },
      nist_controls: ['sc-12', 'sc-13', 'sc-28', 'ac-3'],
    }));
  });

  // ── 7) CMEK in use (Key Vault keys present OR CMK-encrypted storage) ──
  await check('CMEK in use (Resources)', async () => {
    const kvKeys = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.keyvault/vaults/keys" | summarize count_=count() by subscriptionId');
    const cmkStorage = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
      '| where tostring(properties.encryption.keySource) == "Microsoft.Keyvault" ' +
      '| summarize count_=count() by subscriptionId');
    const totalKeys = kvKeys.reduce((a, r) => a + Number(r.count_ ?? 0), 0);
    const totalCmkStorage = cmkStorage.reduce((a, r) => a + Number(r.count_ ?? 0), 0);
    evidence.push(ev('cmek.keys_and_cmek_storage', { keys: totalKeys, cmk_storage_accounts: totalCmkStorage }));
    findings.push(finding({
      rule: 'azure.cmek.in_use', passed: totalKeys > 0 || totalCmkStorage > 0, severity: 'high',
      current: { summary: `${totalKeys} Key Vault key(s) present; ${totalCmkStorage} storage account(s) using CMK.`, observations: { keys: totalKeys, cmk_storage_accounts: totalCmkStorage } },
      target: { summary: 'Customer-managed keys (Key Vault keys) are in use for at-rest encryption of in-scope data.', rationale: 'NIST SC-12, SC-13, SC-28(1). FedRAMP reference builds use CMK rather than Microsoft-managed keys.' },
      gap: { description: 'No customer-managed keys found across the tenant.', affected_resources: [{ type: 'azure_keyvault_key', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Provision Key Vault keys and set `properties.encryption.keySource = Microsoft.Keyvault` on storage / disk encryption sets / SQL.', options: [{ approach: 'Terraform azurerm_key_vault_key + azurerm_storage_account_customer_managed_key.', mechanism: 'terraform', steps: ['Create Key Vault keys with rotation policies', 'Bind storage/disk/SQL to CMK', 'Enforce via built-in policy "Storage accounts should use customer-managed key for encryption"'] }] },
      nist_controls: ['sc-12', 'sc-13', 'sc-28', 'sc-28.1'],
    }));
  });

  // ── 8) Managed disk encryption — disks not on the default platform-only key ──
  await check('Managed disk encryption (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.compute/disks" ' +
      '| extend encType = tostring(properties.encryption.type) ' +
      '| project subscriptionId, name, id, encType');
    const total = rows.length;
    const offenders = rows.filter((r) => r.encType === 'EncryptionAtRestWithPlatformKey' || !r.encType);
    evidence.push(ev('compute.disk_encryption', { total, offenders: offenders.length, sample: offenders.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.compute.disk_encryption', passed: total === 0 || offenders.length === 0, severity: 'medium',
      current: { summary: `${offenders.length}/${total} managed disk(s) use the default platform-managed key (no CMK / no double-encryption).`, observations: { offenders: offenders.slice(0, 50) } },
      target: { summary: 'Managed disks use a customer-managed Disk Encryption Set (or platform-and-customer-key double encryption).', rationale: 'NIST SC-28, SC-28(1).' },
      gap: { description: 'Disks fall back to the default platform-managed key.', affected_resources: offenders.slice(0, 50).map((r: any) => ({ type: 'azure_managed_disk', identifier: r.id, attributes: { encryption: r.encType } })) },
      remediation: { summary: 'Create a Disk Encryption Set bound to a Key Vault CMK and attach disks to it.', options: [{ approach: 'Terraform azurerm_disk_encryption_set + disk_encryption_set_id on disks.', mechanism: 'terraform', steps: ['Create disk_encryption_set bound to a Key Vault key', 'Assign disk_encryption_set_id on each disk', 'Enforce via built-in policy on managed disks'] }] },
      nist_controls: ['sc-28', 'sc-28.1'],
    }));
  });

  // ── 9) NSG: no rule allowing SSH (22) or RDP (3389) from the Internet ──
  await check('NSG open admin ports (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.network/networksecuritygroups" ' +
      '| mv-expand rule = properties.securityRules ' +
      '| extend ruleAccess = tostring(rule.properties.access), ruleDirection = tostring(rule.properties.direction), ' +
      '  srcPrefix = tostring(rule.properties.sourceAddressPrefix), ' +
      '  srcPrefixes = rule.properties.sourceAddressPrefixes, ' +
      '  dstPort = tostring(rule.properties.destinationPortRange), ' +
      '  dstPorts = rule.properties.destinationPortRanges, ' +
      '  ruleName = tostring(rule.name) ' +
      '| where ruleAccess == "Allow" and ruleDirection == "Inbound" ' +
      '| where srcPrefix in ("*", "Internet", "0.0.0.0/0", "0.0.0.0/1") ' +
      '| where dstPort in ("22", "3389", "*") or (dstPorts contains "22") or (dstPorts contains "3389") ' +
      '| project subscriptionId, nsg=name, id, ruleName, srcPrefix, dstPort, dstPorts');
    evidence.push(ev('nsg.open_admin', { offenders: rows.length, sample: rows.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.network.no_open_admin_ports', passed: rows.length === 0, severity: 'high',
      current: { summary: `${rows.length} NSG rule(s) allow SSH/RDP from the Internet.`, observations: { offenders: rows.slice(0, 50) } },
      target: { summary: 'No NSG rule allows inbound SSH (22) or RDP (3389) from `*` / `Internet` / `0.0.0.0/0`.', rationale: 'NIST SC-7, SC-7(3). Eliminate Internet-facing admin surfaces; use Azure Bastion or a jump-host with Conditional Access.' },
      gap: { description: 'NSG rules expose SSH or RDP to the Internet.', affected_resources: rows.slice(0, 50).map((r: any) => ({ type: 'azure_nsg_rule', identifier: `${r.id}::${r.ruleName}`, attributes: { src: r.srcPrefix, dst: r.dstPort } })) },
      remediation: { summary: 'Remove the rule (or restrict its source to a known management network) and adopt Azure Bastion / Conditional-Access-fronted jump hosts.', options: [{ approach: 'Terraform: tighten azurerm_network_security_rule.source_address_prefix.', mechanism: 'terraform', steps: ['Restrict source_address_prefix to a private IP range or specific corp egress IP', 'Deploy Azure Bastion for admin access', 'Enforce via built-in policy "Management ports should be closed on your virtual machines"'] }] },
      nist_controls: ['sc-7', 'sc-7.3'],
    }));
  });

  // ── 10) Public IPs attached to NICs — VMs should be private ──
  await check('Public IPs attached to NICs (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.network/publicipaddresses" ' +
      '| extend assoc = tostring(properties.ipConfiguration.id) ' +
      '| where isnotempty(assoc) and assoc contains "/networkInterfaces/" ' +
      '| project subscriptionId, name, id, ipConfig=assoc');
    evidence.push(ev('network.public_ips_on_nics', { count: rows.length, sample: rows.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.network.no_vm_public_ip', passed: rows.length === 0, severity: 'medium',
      current: { summary: `${rows.length} public IP(s) attached directly to a NIC.`, observations: { sample: rows.slice(0, 50) } },
      target: { summary: 'No VM NIC has a directly-attached public IP; ingress traverses Application Gateway / Front Door / Load Balancer, and egress uses NAT Gateway.', rationale: 'NIST SC-7, AC-4.' },
      gap: { description: 'Public IPs are attached directly to VM NICs.', affected_resources: rows.slice(0, 50).map((r: any) => ({ type: 'azure_public_ip', identifier: r.id, attributes: { ipConfig: r.ipConfig } })) },
      remediation: { summary: 'Detach public IPs from NICs; front workloads via Application Gateway / Front Door; use NAT Gateway for egress.', options: [{ approach: 'Terraform: drop public_ip_address_id from nic ip_configuration.', mechanism: 'terraform', steps: ['Provision Application Gateway / Front Door for ingress', 'Provision NAT Gateway for egress', 'Detach public_ip_address_id from azurerm_network_interface_ip_configuration'] }] },
      nist_controls: ['sc-7', 'ac-4'],
    }));
  });

  // ── 11) Log Analytics workspace with ≥90-day retention ──
  await check('Log Analytics workspace retention (Resources)', async () => {
    const rows = await runKql(client, subscriptions,
      'Resources | where type =~ "microsoft.operationalinsights/workspaces" ' +
      '| extend retention = toint(properties.retentionInDays) ' +
      '| project subscriptionId, name, id, retention');
    const ok = rows.filter((r) => Number(r.retention) >= 90);
    evidence.push(ev('logging.workspace_retention', { total: rows.length, with_90d: ok.length, sample: rows.slice(0, 20) }));
    findings.push(finding({
      rule: 'azure.logging.workspace_retention', passed: ok.length > 0, severity: 'medium',
      current: { summary: `${ok.length}/${rows.length} Log Analytics workspace(s) have ≥ 90-day retention.`, observations: { sample: rows.slice(0, 50) } },
      target: { summary: 'At least one Log Analytics workspace exists with retention ≥ 90 days, and Activity Logs / Diagnostic Settings flow into it.', rationale: 'NIST AU-11, AU-6, SI-4. Log retention floor for FedRAMP.' },
      gap: { description: 'No Log Analytics workspace meets the 90-day retention floor.', affected_resources: [{ type: 'azure_log_analytics_workspace', identifier: 'none', attributes: {} }] },
      remediation: { summary: 'Provision a Log Analytics workspace with retention ≥ 90 days and route Activity Logs + diagnostic settings to it.', options: [{ approach: 'Terraform azurerm_log_analytics_workspace + monitor_diagnostic_setting.', mechanism: 'terraform', steps: ['Set retention_in_days >= 90', 'Create azurerm_monitor_diagnostic_setting for activity logs', 'Repeat per-subscription'] }] },
      nist_controls: ['au-2', 'au-6', 'au-11'],
    }));
  });

  const provider: ProviderBlock = {
    provider: 'azure',
    account_id: subscriptions.join(',') || null,
    evidence, findings, warnings,
  };
  return {
    ksi_id: 'AUDIT-REFARCH-AZURE',
    ksi_name: 'Azure FedRAMP Reference-Architecture Audit',
    ksi_statement:
      'Audit the running Azure environment against FedRAMP reference-architecture hardening expectations ' +
      '(Coalfire Azure RAMPpak-derived, clean-room): Defender for Cloud, FedRAMP Policy initiative, storage ' +
      'public-blob/HTTPS/TLS/network access, Key Vault soft-delete/purge/RBAC, CMK usage, disk encryption, ' +
      'NSG open-admin-ports, no direct VM public IPs, and Log Analytics retention.',
    scope: 'CLOUD',
    frmr_version: ctx.frmrVersion,
    run_id: ctx.runId,
    collected_at: new Date().toISOString(),
    providers: [provider],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings,
      missing_evidence: [],
      alternatives_in_play: 0,
    },
    nist_controls: ['sc-7', 'sc-8', 'sc-12', 'sc-28', 'ac-3', 'ac-4', 'au-2', 'au-6', 'au-11', 'ca-2', 'ca-7', 'cm-6', 'ra-5', 'si-4'],
  };
}
