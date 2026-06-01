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
