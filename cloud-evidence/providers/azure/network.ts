/**
 * Azure network KSI collectors — first three CNA / SVC KSIs.
 *
 *   - KSI-CNA-ULN — Using Logical Networking. NSG flow logs are enabled and
 *     routed to a Log Analytics workspace.
 *   - KSI-CNA-RVP — Reviewing Protections. An Application Gateway / Azure
 *     Front Door Web Application Firewall policy exists and is enabled.
 *   - KSI-SVC-SNT — Securing Network Traffic. Application Gateway listeners
 *     don't accept plaintext HTTP, and storage accounts enforce HTTPS-only.
 *
 * All queryable via Azure Resource Graph — no new permissions beyond AZ-1's
 * `Reader` role. Each KQL call is try/catch'd via the shared runKql helper;
 * failures degrade to warnings, not throws.
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

async function runKql(subscriptions: string[], query: string): Promise<{ rows: any[]; error?: string }> {
  if (subscriptions.length === 0) return { rows: [], error: 'No subscriptions configured (config.azure.subscriptions is empty).' };
  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { return { rows: [], error: `Azure Resource Graph client construction failed: ${e?.message ?? e}` }; }
  const rows: any[] = [];
  let skipToken: string | undefined;
  let pages = 0;
  try {
    do {
      const r = await client.resources({
        subscriptions, query,
        options: { top: 1000, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
      });
      const data = Array.isArray(r?.data) ? r.data : [];
      rows.push(...data);
      skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
    } while (skipToken && ++pages < 50);
  } catch (e: any) {
    return { rows, error: `Resource Graph query failed: ${e?.message ?? e}` };
  }
  return { rows };
}

function subscriptionsOf(ctx: CollectorContext): string[] {
  const list = ctx.azure?.subscription_ids ?? [];
  if (list.length) return list;
  const one = ctx.azure?.subscription_id;
  return one ? [one] : [];
}

// =====================================================================
// KSI-CNA-ULN — Using Logical Networking
// =====================================================================
export async function collectCnaUln(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) NSG flow logs enabled (any flowlog resource present).
  const flowLogs = await runKql(subs,
    'Resources | where type =~ "microsoft.network/networkwatchers/flowlogs" ' +
    '| extend enabled = tobool(properties.enabled), targetId = tostring(properties.targetResourceId), workspaceId = tostring(properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId) ' +
    '| project id, name, subscriptionId, enabled, targetId, workspaceId');
  if (flowLogs.error) warnings.push(flowLogs.error);
  const enabledFlowLogs = flowLogs.rows.filter((r) => r.enabled === true);
  const withWorkspace = enabledFlowLogs.filter((r) => typeof r.workspaceId === 'string' && r.workspaceId.length > 0);
  evidence.push(ev('resourcegraph.nsg_flow_logs', {
    total: flowLogs.rows.length,
    enabled: enabledFlowLogs.length,
    with_workspace: withWorkspace.length,
    sample: enabledFlowLogs.slice(0, 10),
  }));

  findings.push(finding({
    rule: 'azure.cna.uln.nsg_flow_logs_enabled', passed: enabledFlowLogs.length > 0, severity: 'high',
    current: {
      summary: enabledFlowLogs.length > 0
        ? `${enabledFlowLogs.length} enabled NSG flow log(s); ${withWorkspace.length} route to a Log Analytics workspace (Traffic Analytics).`
        : 'No NSG flow logs are enabled — east/west + egress network flow telemetry is unavailable.',
      observations: { enabled: enabledFlowLogs.length, with_workspace: withWorkspace.length },
    },
    target: {
      summary: 'Every in-scope Network Security Group has an enabled flow log routed to a Log Analytics workspace (Traffic Analytics on).',
      rationale: 'NIST AC-4, SC-7, SC-32. FedRAMP requires VPC-equivalent flow log capture + retention.',
    },
    gap: { description: 'NSG flow logs are off (or missing the workspace destination) — network flow records are not being captured or are not investigable.', affected_resources: [{ type: 'azure_nsg_flow_log', identifier: 'none-enabled', attributes: {} }] },
    remediation: {
      summary: 'Provision flow logs on every Network Security Group and route them to the central Log Analytics workspace with Traffic Analytics.',
      options: [
        { approach: 'Built-in Azure Policy DINE: "Flow logs should be configured for every network security group".', mechanism: 'console', steps: ['Policy → Definitions → search "Flow log"', 'Assign at MG / subscription scope', 'Run remediation task to backfill'] },
        { approach: 'Terraform azurerm_network_watcher_flow_log.', mechanism: 'terraform', steps: ['Provision per NSG; storage_account_id + retention_policy + traffic_analytics block with workspace_id'] },
      ],
    },
    nist_controls: ['ac-4', 'sc-7', 'sc-32'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'Same Log Analytics workspace ingests flow logs + diagnostic settings.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CNA-RVP — Reviewing Protections (DoS etc.)
// =====================================================================
export async function collectCnaRvp(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Application Gateway WAF policies, then Azure Front Door WAF policies — either
  // an enabled WAF is sufficient for the FedRAMP "reviewing protections" signal.
  const agw = await runKql(subs,
    'Resources | where type =~ "microsoft.network/applicationgatewaywebapplicationfirewallpolicies" ' +
    '| extend policyState = tostring(properties.policySettings.state), mode = tostring(properties.policySettings.mode) ' +
    '| project id, name, subscriptionId, policyState, mode');
  if (agw.error) warnings.push(agw.error);
  const fd = await runKql(subs,
    'Resources | where type =~ "microsoft.network/frontdoorwebapplicationfirewallpolicies" ' +
    '| extend policyState = tostring(properties.policySettings.enabledState), mode = tostring(properties.policySettings.mode) ' +
    '| project id, name, subscriptionId, policyState, mode');
  if (fd.error) warnings.push(fd.error);

  const enabledAgw = agw.rows.filter((r) => /enabled/i.test(String(r.policyState ?? '')));
  const enabledFd = fd.rows.filter((r) => /enabled/i.test(String(r.policyState ?? '')));
  const enabledWaf = enabledAgw.length + enabledFd.length;
  const totalWaf = agw.rows.length + fd.rows.length;
  evidence.push(ev('resourcegraph.waf_policies', {
    application_gateway_waf: { total: agw.rows.length, enabled: enabledAgw.length, sample: agw.rows.slice(0, 5) },
    front_door_waf: { total: fd.rows.length, enabled: enabledFd.length, sample: fd.rows.slice(0, 5) },
  }));

  findings.push(finding({
    rule: 'azure.cna.rvp.waf_present', passed: enabledWaf > 0, severity: 'high',
    current: {
      summary: enabledWaf > 0
        ? `${enabledWaf} enabled Web Application Firewall polic(ies) — ${enabledAgw.length} Application Gateway + ${enabledFd.length} Front Door (${totalWaf} total).`
        : 'No enabled WAF policies — Application Gateway and Front Door listeners are unprotected from web-application attacks (OWASP Top-10 / DDoS).',
      observations: { enabled_waf: enabledWaf, agw_enabled: enabledAgw.length, fd_enabled: enabledFd.length },
    },
    target: {
      summary: 'At least one enabled Azure WAF policy (Application Gateway or Front Door) protects the public-facing front-door of the cloud service offering, in `Prevention` mode where possible.',
      rationale: 'NIST SC-5, SC-5(1), SC-5(2), SC-7. FedRAMP requires DoS + web-application-attack protection on Internet-facing endpoints.',
    },
    gap: { description: 'No enabled Azure WAF policy exists — there is no managed-ruleset enforcement on the public ingress path.', affected_resources: [{ type: 'azure_waf_policy', identifier: 'none-enabled', attributes: {} }] },
    remediation: {
      summary: 'Provision a WAF policy in Prevention mode and attach it to every public-facing Application Gateway / Front Door instance.',
      options: [
        { approach: 'Terraform azurerm_web_application_firewall_policy (AGW) / azurerm_cdn_frontdoor_firewall_policy (FD).', mechanism: 'terraform', steps: ['policy_settings.state = "Enabled"', 'policy_settings.mode = "Prevention"', 'Attach via azurerm_application_gateway.web_application_firewall_configuration.firewall_policy_id'] },
      ],
    },
    nist_controls: ['sc-5', 'sc-5.1', 'sc-5.2', 'sc-7'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-SVC-SNT — Securing Network Traffic
// =====================================================================
export async function collectSvcSnt(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Application Gateway listeners use HTTPS (or HTTP → HTTPS redirect).
  // `httpListeners[].properties.protocol` is "Http" or "Https"; only the latter
  // is acceptable, unless an explicit redirect rule covers the Http listener
  // (which we *don't* try to model here — it's a follow-up). Any Http listener
  // counts as a failing case.
  const agw = await runKql(subs,
    'Resources | where type =~ "microsoft.network/applicationgateways" ' +
    '| mv-expand listener = properties.httpListeners ' +
    '| extend agwName = name, listenerName = tostring(listener.name), protocol = tostring(listener.properties.protocol) ' +
    '| project subscriptionId, id, agwName, listenerName, protocol');
  if (agw.error) warnings.push(agw.error);
  const httpListeners = agw.rows.filter((r) => /^http$/i.test(String(r.protocol ?? '')));
  evidence.push(ev('resourcegraph.appgateway_listeners', {
    total_listeners: agw.rows.length,
    http_listeners: httpListeners.length,
    sample_http: httpListeners.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.svc.snt.appgateway_https_only', passed: httpListeners.length === 0, severity: 'high',
    current: {
      summary: httpListeners.length === 0
        ? `All ${agw.rows.length} Application Gateway listener(s) use HTTPS (or no AGW deployed).`
        : `${httpListeners.length}/${agw.rows.length} Application Gateway listener(s) accept plaintext HTTP — clients can connect without TLS.`,
      observations: { total: agw.rows.length, http: httpListeners.length },
    },
    target: { summary: 'No Application Gateway listener uses protocol `Http`; either every listener is `Https` or HTTP listeners exist only to redirect to HTTPS.', rationale: 'NIST SC-8, SC-8(1), SC-13. Strong transport encryption on the ingress path.' },
    gap: { description: 'Application Gateway listeners accept plaintext HTTP.', affected_resources: httpListeners.slice(0, 50).map((r: any) => ({ type: 'azure_application_gateway_listener', identifier: `${r.agwName}::${r.listenerName}`, attributes: { protocol: r.protocol } })) },
    remediation: { summary: 'Change every Application Gateway listener protocol to `Https`; for legacy HTTP endpoints, add a redirect rule that 301s to the HTTPS listener.', options: [{ approach: 'Terraform.', mechanism: 'terraform', steps: ['Set http_listener.protocol = "Https" + ssl_certificate', 'For legacy HTTP, replace the listener with a redirect_configuration.target_url pointing at the Https listener'] }] },
    nist_controls: ['sc-8', 'sc-8.1', 'sc-13'],
  }));

  // 2) Storage accounts enforce HTTPS-only.
  const sa = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend https = tobool(properties.supportsHttpsTrafficOnly), tls = tostring(properties.minimumTlsVersion) ' +
    '| project id, name, subscriptionId, https, tls');
  if (sa.error) warnings.push(sa.error);
  const violators = sa.rows.filter((r) => r.https !== true);
  evidence.push(ev('resourcegraph.storage_https_only', { total: sa.rows.length, http_allowed: violators.length, sample: violators.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.svc.snt.storage_https_only', passed: sa.rows.length === 0 || violators.length === 0, severity: 'high',
    current: {
      summary: violators.length === 0
        ? `All ${sa.rows.length} storage account(s) enforce HTTPS-only.`
        : `${violators.length}/${sa.rows.length} storage account(s) allow plaintext HTTP access.`,
      observations: { total: sa.rows.length, http_allowed: violators.length },
    },
    target: { summary: 'Every storage account has `supportsHttpsTrafficOnly = true`.', rationale: 'NIST SC-8, SC-8(1).' },
    gap: { description: 'Storage accounts accept HTTP requests.', affected_resources: violators.slice(0, 50).map((r: any) => ({ type: 'azure_storage_account', identifier: r.id, attributes: { https: r.https } })) },
    remediation: { summary: 'Set `supportsHttpsTrafficOnly = true` on every storage account; enforce tenant-wide via the built-in policy "Secure transfer to storage accounts should be enabled".', options: [{ approach: 'Terraform.', mechanism: 'terraform', steps: ['enable_https_traffic_only = true', 'min_tls_version = "TLS1_2"'] }] },
    nist_controls: ['sc-8', 'sc-8.1'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CNA-MAT — Minimizing Attack Surface
// =====================================================================
/**
 * Two attack-surface checks:
 *   1. Every subnet has an NSG attached. A "default" subnet with no NSG
 *      delegates traffic control to the VNet-level only, expanding the lateral
 *      blast radius.
 *   2. No NSG carries an overly-permissive rule that allows ANY protocol from
 *      ANY source to ANY destination on ANY port. The poster-child rule is the
 *      classic "AllowAll from * to *". Such a rule effectively nullifies the
 *      NSG.
 */
const INTERNET_PREFIXES = ['*', 'Internet', '0.0.0.0/0', '0.0.0.0/1'];

export async function collectCnaMat(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Subnets without an NSG attached.
  const subnets = await runKql(subs,
    'Resources | where type =~ "microsoft.network/virtualnetworks" ' +
    '| mv-expand subnet = properties.subnets ' +
    '| extend subnetName = tostring(subnet.name), nsg = tostring(subnet.properties.networkSecurityGroup.id) ' +
    '| project subscriptionId, vnet = name, vnetId = id, subnetName, nsg');
  if (subnets.error) warnings.push(subnets.error);

  // GatewaySubnet, AzureFirewallSubnet, AzureBastionSubnet, RouteServerSubnet
  // can't carry an NSG on the Azure platform — never count them as "missing NSG".
  const SYSTEM_SUBNETS = new Set(['GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'AzureBastionSubnet', 'RouteServerSubnet']);
  const userSubnets = subnets.rows.filter((s) => !SYSTEM_SUBNETS.has(String(s.subnetName ?? '')));
  const subnetsMissingNsg = userSubnets.filter((s) => !s.nsg);
  evidence.push(ev('resourcegraph.subnets', {
    total: subnets.rows.length,
    user_subnets: userSubnets.length,
    missing_nsg: subnetsMissingNsg.length,
    sample_missing: subnetsMissingNsg.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.cna.mat.all_subnets_have_nsg', passed: subnetsMissingNsg.length === 0, severity: 'high',
    current: {
      summary: subnetsMissingNsg.length === 0
        ? userSubnets.length === 0 ? 'No user subnets observed.' : `All ${userSubnets.length} user subnet(s) have an NSG attached.`
        : `${subnetsMissingNsg.length}/${userSubnets.length} user subnet(s) have no NSG attached — traffic to/from those subnets is governed by the VNet defaults only.`,
      observations: { user_subnets: userSubnets.length, missing_nsg: subnetsMissingNsg.length },
    },
    target: { summary: 'Every user-managed subnet has a Network Security Group attached (system subnets — Gateway / Firewall / Bastion / RouteServer — are exempt because Azure rejects NSG attachment on them).', rationale: 'NIST AC-3, AC-4, SC-7, SC-7(5). Per-subnet enforcement constrains lateral movement.' },
    gap: { description: 'Subnets without an NSG attached expand the lateral blast radius.', affected_resources: subnetsMissingNsg.slice(0, 50).map((s: any) => ({ type: 'azure_subnet', identifier: `${s.vnet}/${s.subnetName}`, attributes: {} })) },
    remediation: { summary: 'Attach an NSG to every user-managed subnet — enforce tenant-wide via the built-in policy "Subnets should be associated with a Network Security Group".', options: [{ approach: 'Terraform azurerm_subnet_network_security_group_association.', mechanism: 'terraform', steps: ['Add azurerm_subnet_network_security_group_association blocks for each subnet', 'Enforce via the built-in DINE policy'] }] },
    nist_controls: ['ac-3', 'ac-4', 'sc-7', 'sc-7.5'],
  }));

  // 2) Overly-permissive NSG rules (Allow * from * to * on any/all ports).
  const allowAllRules = await runKql(subs,
    'Resources | where type =~ "microsoft.network/networksecuritygroups" ' +
    '| mv-expand rule = properties.securityRules ' +
    '| extend access = tostring(rule.properties.access), ' +
    '  direction = tostring(rule.properties.direction), ' +
    '  proto = tostring(rule.properties.protocol), ' +
    '  srcPrefix = tostring(rule.properties.sourceAddressPrefix), ' +
    '  dstPrefix = tostring(rule.properties.destinationAddressPrefix), ' +
    '  dstPort = tostring(rule.properties.destinationPortRange), ' +
    '  ruleName = tostring(rule.name) ' +
    '| where access == "Allow" and proto == "*" ' +
    '  and srcPrefix == "*" and dstPrefix == "*" and dstPort == "*" ' +
    '| project subscriptionId, nsgId = id, nsgName = name, ruleName, direction');
  if (allowAllRules.error) warnings.push(allowAllRules.error);
  evidence.push(ev('resourcegraph.nsg_allow_all_rules', { offenders: allowAllRules.rows.length, sample: allowAllRules.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.cna.mat.no_nsg_allow_all_rule', passed: allowAllRules.rows.length === 0, severity: 'critical',
    current: {
      summary: allowAllRules.rows.length === 0
        ? 'No NSG carries a fully-wildcard `Allow * from * to *` rule.'
        : `${allowAllRules.rows.length} NSG rule(s) Allow * from * to * on all ports — the NSG is effectively unconstrained.`,
      observations: { offenders: allowAllRules.rows.slice(0, 50) },
    },
    target: { summary: 'No NSG has a rule that allows any protocol from any source to any destination on any port. Wildcard rules of that breadth defeat the purpose of the NSG.', rationale: 'NIST AC-4, SC-7, SC-7(5).' },
    gap: { description: 'Wildcard Allow rules nullify NSG enforcement.', affected_resources: allowAllRules.rows.slice(0, 50).map((r: any) => ({ type: 'azure_nsg_rule', identifier: `${r.nsgName}::${r.ruleName}`, attributes: { direction: r.direction } })) },
    remediation: { summary: 'Delete or scope the offending rules to the minimum required source / destination / port set.', options: [{ approach: 'Terraform: tighten azurerm_network_security_rule.', mechanism: 'terraform', steps: ['Replace `*` with a specific CIDR / service tag', 'Replace `*` destination_port_range with the actual port the service uses', 'Re-run vitest + verify the offender count drops to 0'] }] },
    nist_controls: ['ac-4', 'sc-7', 'sc-7.5'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CNA-RNT — Restricting Network Traffic
// =====================================================================
/**
 * Two restriction checks:
 *   1. No NSG INBOUND rule allows traffic from `*` / `Internet` / `0.0.0.0/0`
 *      on ALL ports (any catch-all internet ingress, not just the SSH/RDP
 *      check that lives on the reference-arch audit).
 *   2. No NSG OUTBOUND rule allows traffic to `*` / `Internet` / `0.0.0.0/0`
 *      on ALL ports — egress should be constrained, not wide open.
 */
export async function collectCnaRnt(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const rules = await runKql(subs,
    'Resources | where type =~ "microsoft.network/networksecuritygroups" ' +
    '| mv-expand rule = properties.securityRules ' +
    '| extend access = tostring(rule.properties.access), ' +
    '  direction = tostring(rule.properties.direction), ' +
    '  srcPrefix = tostring(rule.properties.sourceAddressPrefix), ' +
    '  dstPrefix = tostring(rule.properties.destinationAddressPrefix), ' +
    '  dstPort = tostring(rule.properties.destinationPortRange), ' +
    '  ruleName = tostring(rule.name) ' +
    '| where access == "Allow" ' +
    '| project subscriptionId, nsgId = id, nsgName = name, ruleName, access, direction, srcPrefix, dstPrefix, dstPort');
  if (rules.error) warnings.push(rules.error);

  // Defensive JS-side filter: only count Allow rules. The KQL `where access == "Allow"`
  // is the primary gate, but we re-check in JS so the contract doesn't silently
  // rely on Resource Graph behaviour.
  const allRules = rules.rows.filter((r) => String(r.access ?? '') === 'Allow' || r.access === undefined);
  const ingressWildcards = allRules.filter((r) =>
    String(r.direction ?? '') === 'Inbound' &&
    INTERNET_PREFIXES.includes(String(r.srcPrefix ?? '')) &&
    String(r.dstPort ?? '') === '*',
  );
  const egressWildcards = allRules.filter((r) =>
    String(r.direction ?? '') === 'Outbound' &&
    INTERNET_PREFIXES.includes(String(r.dstPrefix ?? '')) &&
    String(r.dstPort ?? '') === '*',
  );
  evidence.push(ev('resourcegraph.nsg_traffic_rules', {
    total_allow_rules: allRules.length,
    ingress_wildcards: ingressWildcards.length,
    egress_wildcards: egressWildcards.length,
    sample_ingress: ingressWildcards.slice(0, 20),
    sample_egress: egressWildcards.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.cna.rnt.no_unrestricted_ingress', passed: ingressWildcards.length === 0, severity: 'high',
    current: {
      summary: ingressWildcards.length === 0
        ? 'No NSG inbound rule allows all ports from `*` / `Internet` / `0.0.0.0/0`.'
        : `${ingressWildcards.length} NSG inbound rule(s) allow all ports from "*" / "Internet".`,
      observations: { offenders: ingressWildcards.slice(0, 50) },
    },
    target: { summary: 'NSG inbound rules name a specific destination port (or constrained port-range) rather than `*` when the source is `*` / `Internet`.', rationale: 'NIST AC-4, SC-7, SC-7(5). Restrict inbound; route through Application Gateway / Bastion / Azure Firewall.' },
    gap: { description: 'Inbound traffic from the Internet is unrestricted on at least one NSG.', affected_resources: ingressWildcards.slice(0, 50).map((r: any) => ({ type: 'azure_nsg_rule', identifier: `${r.nsgName}::${r.ruleName}`, attributes: { src: r.srcPrefix, dstPort: r.dstPort } })) },
    remediation: { summary: 'Tighten the listed rules: replace the `*` destination port with the specific port range your service needs, or front the workload with Application Gateway / Azure Firewall.', options: [{ approach: 'Terraform.', mechanism: 'terraform', steps: ['azurerm_network_security_rule.destination_port_range = "443"  # (or a tight range)', 'Restrict source_address_prefix to a managed CIDR / service tag'] }] },
    nist_controls: ['ac-4', 'sc-7', 'sc-7.5'],
  }));

  findings.push(finding({
    rule: 'azure.cna.rnt.no_unrestricted_egress', passed: egressWildcards.length === 0, severity: 'medium',
    current: {
      summary: egressWildcards.length === 0
        ? 'No NSG outbound rule allows all ports to `*` / `Internet` / `0.0.0.0/0`.'
        : `${egressWildcards.length} NSG outbound rule(s) allow all ports to "*" / "Internet" — egress is essentially unconstrained.`,
      observations: { offenders: egressWildcards.slice(0, 50) },
    },
    target: { summary: 'NSG outbound rules constrain destination + port, or workloads egress through a centralised Azure Firewall / NAT Gateway with rules.', rationale: 'NIST AC-4, SC-7. Constraining egress limits data exfil + C2.' },
    gap: { description: 'Egress traffic to the Internet is wildcard-permitted on at least one NSG.', affected_resources: egressWildcards.slice(0, 50).map((r: any) => ({ type: 'azure_nsg_rule', identifier: `${r.nsgName}::${r.ruleName}`, attributes: { dst: r.dstPrefix, dstPort: r.dstPort } })) },
    remediation: {
      summary: 'Restrict the egress rules to required destinations + ports, or front egress through Azure Firewall with FQDN allow-lists.',
      options: [
        { approach: 'Centralised egress via Azure Firewall.', mechanism: 'terraform', steps: ['Provision an Azure Firewall in the hub VNet', 'Configure FQDN + IP allow-rules', 'Route all VNet egress through the firewall via a User-Defined Route'] },
        { approach: 'Tighten the NSG outbound rule.', mechanism: 'terraform', steps: ['destination_address_prefix = <specific CIDR / service tag>', 'destination_port_range = <required port set>'] },
      ],
    },
    nist_controls: ['ac-4', 'sc-7'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
