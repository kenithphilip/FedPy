/**
 * Azure Monitor / Sentinel logging collectors.
 *
 * Two KSIs in this slice, both queryable via Azure Resource Graph (no new
 * Graph permissions — the Reader role at AZ-1 covers them):
 *
 *   - KSI-MLA-LET — Logging Event Types. Are diagnostic settings actually
 *     attached to in-scope resources, and is there a Log Analytics workspace
 *     to ingest the data?
 *   - KSI-MLA-OSM — Operating SIEM Capability. Is there a Log Analytics
 *     workspace + a Microsoft Sentinel solution onboarded against it?
 *
 * Read-only via the existing Azure Resource Graph client (guardrail-wrapped).
 * Each KQL query is try/catch'd; failures surface as warnings, not throws.
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

/** Run one KQL query across the given subscriptions, paginating fully. */
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
  // Fall back to the single subscription_id field for backward compat with
  // earlier IAM-style collectors that didn't carry the multi-sub list.
  const one = ctx.azure?.subscription_id;
  return one ? [one] : [];
}

// =====================================================================
// KSI-MLA-LET — Logging Event Types
// =====================================================================
export async function collectMlaLet(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Any diagnostic settings present on any resource in the tenancy.
  const diag = await runKql(subs,
    'Resources | where type =~ "microsoft.insights/diagnosticsettings" ' +
    '| project id, subscriptionId, name, properties ' +
    '| summarize total=count(), bySub=make_set(subscriptionId)');
  if (diag.error) warnings.push(diag.error);
  const diagTotal = Number(diag.rows[0]?.total ?? 0);
  const subsWithDiag = (diag.rows[0]?.bySub as string[] | undefined ?? []).length;
  evidence.push(ev('resourcegraph.diagnostic_settings.total', { total: diagTotal, subscriptions_with_diag: subsWithDiag, subscriptions_total: subs.length }));

  findings.push(finding({
    rule: 'azure.diagnostic_settings_present', passed: diagTotal > 0, severity: 'high',
    current: {
      summary: diagTotal > 0
        ? `${diagTotal} diagnostic setting(s) configured across ${subsWithDiag}/${subs.length} subscription(s).`
        : 'No diagnostic settings configured on any resource in the configured subscription(s).',
      observations: { total: diagTotal, subscriptions_with_diag: subsWithDiag },
    },
    target: {
      summary: 'In-scope resource types (storage, key vaults, SQL, app gateways, network security groups, app services, etc.) have a `diagnosticSettings` child resource routing the security-relevant log categories to a Log Analytics workspace, Storage Account, or Event Hub.',
      rationale: 'NIST AU-2, AU-3, AU-12. FedRAMP requires that the CSO log the event types listed in its SSP AU-2 narrative.',
    },
    gap: { description: 'Resources do not have diagnostic settings attached — security-relevant events are not being captured.', affected_resources: [{ type: 'azure_diagnostic_settings', identifier: 'tenancy-wide', attributes: {} }] },
    remediation: {
      summary: 'Enable diagnostic settings on every in-scope resource type via Azure Policy (built-in initiative "Enable Audit category group resource logging for [resource type] to Log Analytics").',
      options: [
        { approach: 'Built-in Azure Policy initiatives (DINE — Deploy-If-Not-Exists).', mechanism: 'console', steps: ['Policy → Definitions → search "Enable Audit category group resource logging"', 'Assign at MG/subscription scope', 'Run remediation tasks to backfill existing resources'] },
        { approach: 'Terraform azurerm_monitor_diagnostic_setting per resource.', mechanism: 'terraform', steps: ['Define azurerm_monitor_diagnostic_setting blocks per critical resource', 'Point at a shared Log Analytics workspace + (optionally) Storage Account for long-term archive'] },
      ],
    },
    nist_controls: ['au-2', 'au-3', 'au-12'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-OSM', relationship: 'shares-remediation', note: 'The workspace from MLA-OSM is the ingest target for these diagnostic settings.' }],
  }));

  // 2) Log Analytics workspace present (substrate for the diag settings above).
  const ws = await runKql(subs,
    'Resources | where type =~ "microsoft.operationalinsights/workspaces" ' +
    '| project subscriptionId, name, id, retention=toint(properties.retentionInDays), sku=tostring(properties.sku.name) ' +
    '| order by retention desc');
  if (ws.error) warnings.push(ws.error);
  const wsCount = ws.rows.length;
  evidence.push(ev('resourcegraph.log_analytics_workspaces', { count: wsCount, sample: ws.rows.slice(0, 10) }));

  findings.push(finding({
    rule: 'azure.log_analytics_workspace_present', passed: wsCount > 0, severity: 'high',
    current: {
      summary: wsCount > 0
        ? `${wsCount} Log Analytics workspace(s) available as a log-ingest substrate.`
        : 'No Log Analytics workspace exists in the configured subscription(s) — diagnostic settings have nowhere to send logs.',
      observations: { workspace_count: wsCount },
    },
    target: { summary: 'At least one Log Analytics workspace exists in the tenancy to ingest diagnostic-setting output.', rationale: 'NIST AU-2, AU-3, AU-12.' },
    gap: { description: 'No Log Analytics workspace exists.', affected_resources: [{ type: 'azure_log_analytics_workspace', identifier: 'none', attributes: {} }] },
    remediation: { summary: 'Provision a Log Analytics workspace and reference it from diagnostic settings + Sentinel.', options: [{ approach: 'Terraform azurerm_log_analytics_workspace.', mechanism: 'terraform', steps: ['retention_in_days = 90 (or 365 for High)', 'sku = "PerGB2018"', 'Reference from azurerm_monitor_diagnostic_setting blocks'] }] },
    nist_controls: ['au-2', 'au-12'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-MLA-OSM — Operating SIEM Capability
// =====================================================================
export async function collectMlaOsm(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Workspace present (substrate for SIEM).
  const ws = await runKql(subs,
    'Resources | where type =~ "microsoft.operationalinsights/workspaces" | project id, name, subscriptionId');
  if (ws.error) warnings.push(ws.error);
  evidence.push(ev('resourcegraph.log_analytics_workspaces', { count: ws.rows.length }));

  findings.push(finding({
    rule: 'azure.siem.workspace_substrate_present', passed: ws.rows.length > 0, severity: 'high',
    current: { summary: ws.rows.length > 0 ? `${ws.rows.length} Log Analytics workspace(s) — SIEM substrate available.` : 'No Log Analytics workspace — no substrate to run Sentinel on.', observations: { workspace_count: ws.rows.length } },
    target: { summary: 'At least one Log Analytics workspace exists, ready for Sentinel onboarding.', rationale: 'NIST AU-6, AU-6(1), AU-7. Sentinel requires a workspace.' },
    gap: { description: 'No Log Analytics workspace exists in the tenancy.', affected_resources: [{ type: 'azure_log_analytics_workspace', identifier: 'none', attributes: {} }] },
    remediation: { summary: 'Provision a Log Analytics workspace (see MLA-LET) before onboarding Sentinel.', options: [{ approach: 'Terraform azurerm_log_analytics_workspace.', mechanism: 'terraform', steps: ['retention_in_days = 90+', 'sku = "PerGB2018"'] }] },
    nist_controls: ['au-2', 'au-6'],
  }));

  // 2) Microsoft Sentinel deployed on a workspace — either legacy solutions
  // (microsoft.operationsmanagement/solutions starting with 'SecurityInsights')
  // or the newer onboardingstates resource.
  const solutions = await runKql(subs,
    'Resources | where type =~ "microsoft.operationsmanagement/solutions" ' +
    '| where name startswith "SecurityInsights" ' +
    '| project id, name, subscriptionId');
  if (solutions.error) warnings.push(solutions.error);
  const onboarding = await runKql(subs,
    'Resources | where type =~ "microsoft.securityinsights/onboardingstates" ' +
    '| project id, name, subscriptionId');
  if (onboarding.error) warnings.push(onboarding.error);
  const sentinelDeployed = solutions.rows.length + onboarding.rows.length;
  evidence.push(ev('resourcegraph.sentinel_indicators', {
    legacy_solutions: solutions.rows.length,
    onboarding_states: onboarding.rows.length,
    sample_solutions: solutions.rows.slice(0, 5),
    sample_onboarding: onboarding.rows.slice(0, 5),
  }));

  findings.push(finding({
    rule: 'azure.siem.sentinel_deployed', passed: sentinelDeployed > 0, severity: 'high',
    current: {
      summary: sentinelDeployed > 0
        ? `Microsoft Sentinel detected via ${solutions.rows.length} legacy SecurityInsights solution(s) + ${onboarding.rows.length} onboardingstate(s).`
        : 'No Microsoft Sentinel deployment detected (no SecurityInsights solution, no onboarding state).',
      observations: { legacy_solutions: solutions.rows.length, onboarding_states: onboarding.rows.length },
    },
    target: {
      summary: 'Microsoft Sentinel is onboarded on a Log Analytics workspace, providing the SIEM capability FedRAMP requires for centralized alerting + investigation.',
      rationale: 'NIST AU-2, AU-6, AU-6(1), AU-7. Sentinel is the FedRAMP-authorized first-party SIEM on Azure.',
    },
    gap: { description: 'Sentinel is not onboarded on any workspace — no centralized SIEM analytics over the diagnostic-setting output.', affected_resources: [{ type: 'azure_sentinel', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Onboard Microsoft Sentinel on the workspace and enable the FedRAMP-aligned analytics rules.',
      options: [
        { approach: 'Azure CLI onboarding.', mechanism: 'cli', steps: ['az sentinel onboarding-state create --resource-group <rg> --workspace-name <ws> --name "default"', 'Enable analytics rules from the FedRAMP-aligned content hub solution'] },
        { approach: 'Terraform azurerm_sentinel_log_analytics_workspace_onboarding.', mechanism: 'terraform', steps: ['Reference your azurerm_log_analytics_workspace', 'Enable customer_managed_key if required for FedRAMP High'] },
      ],
    },
    nist_controls: ['au-2', 'au-6', 'au-6.1', 'au-7'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-LET', relationship: 'depends-on', note: 'Sentinel needs diagnostic settings (LET) to have data to analyze.' }],
  }));

  // Awareness alternative: 3rd-party SIEM (Splunk, Datadog, etc.) consuming the
  // workspace via diagnostic-export or Event Hub — common pattern that this
  // collector cannot directly detect from ARM data.
  const ksiLevelAlternatives = [
    {
      via: '3rd-party SIEM consuming Log Analytics / Event Hub',
      description: 'A non-Microsoft SIEM (Splunk, Datadog, Chronicle, etc.) may be consuming Azure logs via the Log Analytics export, Event Hub, or Azure Monitor Logs API. This collector cannot see that flow from ARM data alone.',
      evidence_required: ['SIEM-vendor attestation', 'Sample alert + investigation showing Azure log sources'],
      detected: false, detection_signals: [],
    },
  ];

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: ksiLevelAlternatives };
}
