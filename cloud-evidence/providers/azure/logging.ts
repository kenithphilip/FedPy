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
import type { ProviderBlock, RawEvidence, Finding, AlternativeSatisfier } from '../../core/envelope.ts';
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

// =====================================================================
// KSI-MLA-ALA — Authorizing Log Access
// =====================================================================
/**
 * Least-privileged RBAC on log data. The strongest positive signal we can pull
 * from Resource Graph is: explicit `Log Analytics Reader` role assignments
 * scoped at Log Analytics workspaces. That role grants read-only on the
 * workspace's logs — operators are reaching for the right primitive instead of
 * blanket `Reader` / `Contributor` / `Owner`.
 */
const LOG_ANALYTICS_READER_ROLE_DEF = '73c42c96-874c-492b-b04d-ab87d138a893';
const OWNER_ROLE_DEF = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
const CONTRIBUTOR_ROLE_DEF = 'b24988ac-6180-42a0-ab88-20f7382dd24c';

export async function collectMlaAla(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Role assignments scoped specifically at Log Analytics workspaces.
  // Resource Graph exposes role assignments via the `authorizationresources`
  // table; properties.scope is the resource-id substring we filter on.
  const assignments = await runKql(subs,
    'authorizationresources ' +
    '| where type =~ "microsoft.authorization/roleassignments" ' +
    '| extend scope = tostring(properties.scope), roleDef = tostring(properties.roleDefinitionId) ' +
    '| where scope contains "/providers/microsoft.operationalinsights/workspaces/" ' +
    '| project id, scope, roleDef, principalId=tostring(properties.principalId)');
  if (assignments.error) warnings.push(assignments.error);

  const readerCount = assignments.rows.filter((r) => String(r.roleDef ?? '').endsWith(`/${LOG_ANALYTICS_READER_ROLE_DEF}`)).length;
  const broadOwnerOrContributor = assignments.rows.filter((r) => {
    const id = String(r.roleDef ?? '');
    return id.endsWith(`/${OWNER_ROLE_DEF}`) || id.endsWith(`/${CONTRIBUTOR_ROLE_DEF}`);
  }).length;

  evidence.push(ev('resourcegraph.workspace_role_assignments', {
    total_workspace_scoped: assignments.rows.length,
    log_analytics_reader: readerCount,
    owner_or_contributor: broadOwnerOrContributor,
    sample: assignments.rows.slice(0, 20),
  }));

  // ── Finding 1: Log Analytics Reader is in use on a workspace ──
  findings.push(finding({
    rule: 'azure.mla.ala.log_analytics_reader_assigned', passed: readerCount > 0, severity: 'medium',
    current: {
      summary: readerCount > 0
        ? `${readerCount} Log Analytics Reader role assignment(s) at workspace scope — operators are using the dedicated read-only role.`
        : 'No Log Analytics Reader assignments at workspace scope — read access to logs likely flows through broader roles.',
      observations: { reader_count: readerCount, broad_count: broadOwnerOrContributor, total: assignments.rows.length },
    },
    target: {
      summary: 'At least one explicit `Log Analytics Reader` (role-def `73c42c96-…`) assignment exists at a Log Analytics workspace scope — read-only access to log data follows least privilege.',
      rationale: 'NIST SI-11, AC-3, AC-6. FedRAMP requires least-privilege access to security-relevant logs.',
    },
    gap: { description: 'Read access to log data may rely on broader `Reader` / `Contributor` / `Owner` roles inherited from above the workspace, not the dedicated read-only role.', affected_resources: [{ type: 'azure_log_analytics_workspace_rbac', identifier: 'no-reader-role-found', attributes: {} }] },
    remediation: {
      summary: 'Grant the runtime SOC / on-call group the `Log Analytics Reader` role at the workspace scope and remove broader role inheritance where it isn\'t needed.',
      options: [
        { approach: 'Terraform azurerm_role_assignment with role_definition_name = "Log Analytics Reader".', mechanism: 'terraform', steps: ['Identify SOC / on-call group object id', 'Assign Log Analytics Reader scoped at azurerm_log_analytics_workspace.id', 'Remove inherited Reader/Contributor on the workspace where possible'] },
      ],
    },
    nist_controls: ['si-11', 'ac-3', 'ac-6'],
  }));

  // ── Finding 2: broad Owner/Contributor at workspace scope is bounded ──
  // Pass if there are 0 (best) or some have a corresponding Reader (signal that
  // the operator has at least documented the constrained read role too).
  findings.push(finding({
    rule: 'azure.mla.ala.no_broad_workspace_admins', passed: broadOwnerOrContributor === 0, severity: 'low',
    current: {
      summary: broadOwnerOrContributor === 0
        ? 'No Owner / Contributor role assignments scoped directly at a Log Analytics workspace.'
        : `${broadOwnerOrContributor} Owner / Contributor assignment(s) scoped at a workspace — review whether they're necessary.`,
      observations: { broad_count: broadOwnerOrContributor, sample: assignments.rows.slice(0, 50) },
    },
    target: { summary: 'No `Owner` or `Contributor` role assignment scopes directly at a Log Analytics workspace — admin scopes inherit from above; read uses `Log Analytics Reader`.', rationale: 'NIST AC-6, SI-11.' },
    gap: { description: 'Broad admin roles assigned directly at a Log Analytics workspace expand the surface that can modify or wipe log data.', affected_resources: [{ type: 'azure_log_analytics_workspace_rbac', identifier: 'broad-roles-at-workspace', attributes: { count: broadOwnerOrContributor } }] },
    remediation: { summary: 'Audit the listed broad-role assignments; demote unneeded ones or move them to a higher scope and rely on inheritance only when necessary.', options: [{ approach: 'Remove the assignment via az CLI.', mechanism: 'cli', steps: ['az role assignment delete --assignee <principal> --role <Owner|Contributor> --scope <workspace>'] }] },
    nist_controls: ['ac-6'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-MLA-RVL — Reviewing Logs
// =====================================================================
const RVL_RETENTION_FLOOR_DAYS = 90;

export async function collectMlaRvl(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Workspace retention — at least one workspace at floor.
  const ws = await runKql(subs,
    'Resources | where type =~ "microsoft.operationalinsights/workspaces" ' +
    '| project subscriptionId, id, name, retention=toint(properties.retentionInDays)');
  if (ws.error) warnings.push(ws.error);
  const wsAtFloor = ws.rows.filter((r) => Number(r.retention ?? 0) >= RVL_RETENTION_FLOOR_DAYS).length;
  evidence.push(ev('resourcegraph.workspace_retention', { total: ws.rows.length, at_floor: wsAtFloor, sample: ws.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.mla.rvl.workspace_retention_at_floor', passed: wsAtFloor > 0, severity: 'high',
    current: {
      summary: `${wsAtFloor}/${ws.rows.length} Log Analytics workspace(s) have retention ≥ ${RVL_RETENTION_FLOOR_DAYS} days.`,
      observations: { at_floor: wsAtFloor, total: ws.rows.length, floor_days: RVL_RETENTION_FLOOR_DAYS },
    },
    target: { summary: `At least one Log Analytics workspace retains data for ≥ ${RVL_RETENTION_FLOOR_DAYS} days (long enough to support FedRAMP-required investigations).`, rationale: 'NIST AU-6, AU-11.' },
    gap: { description: `No Log Analytics workspace meets the ${RVL_RETENTION_FLOOR_DAYS}-day retention floor.`, affected_resources: [{ type: 'azure_log_analytics_workspace', identifier: 'retention<floor', attributes: { floor_days: RVL_RETENTION_FLOOR_DAYS } }] },
    remediation: { summary: `Raise retention_in_days on at least one workspace to ${RVL_RETENTION_FLOOR_DAYS} (consider 365+ for FedRAMP High).`, options: [{ approach: 'Terraform azurerm_log_analytics_workspace.', mechanism: 'terraform', steps: [`retention_in_days = ${RVL_RETENTION_FLOOR_DAYS}`, 'Long-term archive: enable a per-table data export to a Storage Account with immutability.'] }] },
    nist_controls: ['au-6', 'au-11'],
  }));

  // 2) Active log review — scheduled query rules OR Sentinel analytic rules.
  const sqr = await runKql(subs,
    'Resources | where type =~ "microsoft.insights/scheduledqueryrules" | project id, subscriptionId, name');
  if (sqr.error) warnings.push(sqr.error);
  const sentinel = await runKql(subs,
    'Resources | where type =~ "microsoft.securityinsights/alertrules" | project id, subscriptionId, name');
  if (sentinel.error) warnings.push(sentinel.error);
  const totalRules = sqr.rows.length + sentinel.rows.length;
  evidence.push(ev('resourcegraph.alert_rules', { scheduled_query_rules: sqr.rows.length, sentinel_alert_rules: sentinel.rows.length }));

  findings.push(finding({
    rule: 'azure.mla.rvl.alert_rules_present', passed: totalRules > 0, severity: 'high',
    current: {
      summary: totalRules > 0
        ? `${totalRules} scheduled / Sentinel alert rule(s) actively reviewing logs (${sqr.rows.length} Azure Monitor + ${sentinel.rows.length} Sentinel).`
        : 'No scheduled query rules or Sentinel alert rules — logs are being collected but not actively reviewed.',
      observations: { scheduled_query_rules: sqr.rows.length, sentinel_alert_rules: sentinel.rows.length },
    },
    target: { summary: 'At least one alert rule (Azure Monitor scheduled query OR Sentinel analytic rule) is actively querying log data on a schedule.', rationale: 'NIST AU-6, AU-6(1), SI-4. Active review, not just collection.' },
    gap: { description: 'Logs are collected but no scheduled or Sentinel analytic rule queries them on a schedule.', affected_resources: [{ type: 'azure_alert_rule', identifier: 'none', attributes: {} }] },
    remediation: { summary: 'Enable a set of analytic rules — Sentinel provides FedRAMP-aligned rule templates out of the box.', options: [{ approach: 'Sentinel content hub.', mechanism: 'console', steps: ['Sentinel → Content hub → search "FedRAMP" / "NIST"', 'Install the relevant solution; enable the bundled analytic rules'] }] },
    nist_controls: ['au-6', 'au-6.1', 'si-4'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CMT-LMC — Logging Changes
// =====================================================================
export async function collectCmtLmc(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Subscription-scope diagnostic settings (Activity Log → workspace / SA).
  // Subscription-scope settings appear in Resource Graph with an id beginning
  // `/subscriptions/<sub>/providers/microsoft.insights/diagnosticsettings`.
  const subDiag = await runKql(subs,
    'Resources | where type =~ "microsoft.insights/diagnosticsettings" ' +
    '| extend isSubScope = tobool(id matches regex "^/subscriptions/[0-9a-fA-F-]+/providers/microsoft.insights/diagnosticsettings") ' +
    '| where isSubScope ' +
    '| project id, name, subscriptionId, workspaceId=tostring(properties.workspaceId), storageId=tostring(properties.storageAccountId)');
  if (subDiag.error) warnings.push(subDiag.error);
  // Defensive JS-side filter: only count rows whose id is at subscription scope.
  // The KQL `where isSubScope` filter is the primary guard, but we re-check in JS
  // so the collector contract doesn't silently rely on Resource Graph behaviour.
  // Match any non-slash subscription-id token between `/subscriptions/` and the
  // immediately-following `/providers/microsoft.insights/diagnosticsettings`.
  // The strict-GUID check would be cosmetic here — Azure's ARM REST guarantees
  // a GUID in production, and the anchor on the immediate `/providers/...` path
  // is what actually rejects child-resource scopes (e.g. storageaccount/sa/...).
  const subScopeRegex = /^\/subscriptions\/[^/]+\/providers\/microsoft\.insights\/diagnosticsettings/i;
  const subScopeRows = subDiag.rows.filter((r) => typeof r.id === 'string' && subScopeRegex.test(r.id));
  const coveredSubs = new Set(subScopeRows.map((r) => String(r.subscriptionId ?? '')));
  evidence.push(ev('resourcegraph.subscription_diagnostic_settings', {
    rows_returned: subDiag.rows.length,
    settings_at_subscription_scope: subScopeRows.length,
    subscriptions_covered: coveredSubs.size,
    subscriptions_configured: subs.length,
    sample: subScopeRows.slice(0, 20),
  }));

  findings.push(finding({
    rule: 'azure.cmt.lmc.activity_log_exported', passed: coveredSubs.size === subs.length && subs.length > 0, severity: 'high',
    current: {
      summary: subs.length === 0
        ? 'No subscriptions configured to evaluate.'
        : `${coveredSubs.size}/${subs.length} subscription(s) export the Activity Log via a diagnostic setting.`,
      observations: { subscriptions_covered: coveredSubs.size, subscriptions_configured: subs.length, sample: [...coveredSubs] },
    },
    target: {
      summary: 'Every in-scope subscription has a diagnostic setting at subscription scope exporting the Activity Log to a Log Analytics workspace, Storage Account, or Event Hub.',
      rationale: 'NIST AU-2, AU-3, AU-12, CM-3(1), CM-5(1). Configuration changes must be logged.',
    },
    gap: { description: 'One or more subscriptions are not exporting the Activity Log — configuration changes for those subscriptions are not being captured beyond Azure\'s default 90-day Activity Log buffer.', affected_resources: (() => { const offenders = [...subs].filter((s) => !coveredSubs.has(s)).slice(0, 50).map((s) => ({ type: 'azure_subscription', identifier: s, attributes: {} })); return offenders.length ? offenders : [{ type: 'azure_subscription', identifier: 'subscription', name: 'no subscription configured to evaluate — Activity Log export indeterminate', attributes: { subscriptions_configured: subs.length } }]; })() },
    remediation: {
      summary: 'Create a subscription-scope diagnostic setting on every subscription pointing at the central Log Analytics workspace.',
      options: [
        { approach: 'Terraform azurerm_monitor_diagnostic_setting at /subscriptions/<sub>.', mechanism: 'terraform', steps: ['For each subscription, declare azurerm_monitor_diagnostic_setting with target_resource_id = "/subscriptions/<sub>"', 'enabled_log { category = "Administrative" } (+ other categories per FedRAMP AU-2 narrative)', 'log_analytics_workspace_id = <shared workspace>'] },
        { approach: 'Built-in policy "Configure Azure Activity logs to stream to specified Log Analytics workspace".', mechanism: 'console', steps: ['Policy → Definitions → assign DINE policy at MG scope', 'Run a remediation task to backfill existing subscriptions'] },
      ],
    },
    nist_controls: ['au-2', 'au-12', 'cm-3.1', 'cm-5.1'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'Same Resource-Logs / diagnostic-settings pipeline.' }],
  }));

  // 2) Change Tracking solution (or Defender / VM Insights change tracking) present.
  const changeTracking = await runKql(subs,
    'Resources | where type =~ "microsoft.operationsmanagement/solutions" and name startswith "ChangeTracking" ' +
    '| project id, name, subscriptionId');
  if (changeTracking.error) warnings.push(changeTracking.error);
  evidence.push(ev('resourcegraph.change_tracking_solutions', { count: changeTracking.rows.length, sample: changeTracking.rows.slice(0, 10) }));

  findings.push(finding({
    rule: 'azure.cmt.lmc.change_tracking_enabled', passed: changeTracking.rows.length > 0, severity: 'medium',
    current: {
      summary: changeTracking.rows.length > 0
        ? `${changeTracking.rows.length} Change Tracking solution(s) deployed.`
        : 'No Change Tracking solution detected (no microsoft.operationsmanagement/solutions starting with "ChangeTracking").',
      observations: { count: changeTracking.rows.length },
    },
    target: { summary: 'Azure Change Tracking (or a SIEM-side equivalent) is enabled to capture OS-level + file-level changes on in-scope VMs.', rationale: 'NIST CM-3, CM-3(1), CM-5(1).' },
    gap: { description: 'No Change Tracking solution is deployed — VM-level changes (registry / files / services / installed software) are not being tracked.', affected_resources: [{ type: 'azure_change_tracking_solution', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Enable Change Tracking via Azure Monitor or migrate to the newer Defender for Servers change-tracking agent.',
      options: [
        { approach: 'Terraform azurerm_log_analytics_solution "ChangeTracking".', mechanism: 'terraform', steps: ['Create the solution resource targeting the central workspace', 'Onboard VMs via the Azure Monitor Agent extension'] },
      ],
    },
    nist_controls: ['cm-3', 'cm-3.1', 'cm-5.1'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-MLA-EVC — Evaluating Configurations
// =====================================================================
/**
 * Microsoft Defender for Cloud generates continuous security assessments on
 * every in-scope resource (`microsoft.security/assessments`). Their presence is
 * the strongest automatable signal for "actively evaluating + testing the
 * configuration of machine-based information resources" — a richer evaluator
 * than the Azure Policy engine (CNA-EIS) because each assessment carries a
 * per-resource Healthy / Unhealthy status that maps directly to FedRAMP CM-6 /
 * RA-5 evidence.
 */
export async function collectMlaEvc(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const assess = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/assessments" ' +
    '| extend status = tostring(properties.status.code) ' +
    '| summarize total = count(), unhealthy = countif(status == "Unhealthy"), healthy = countif(status == "Healthy") by subscriptionId');
  if (assess.error) warnings.push(assess.error);
  const totals = assess.rows.reduce(
    (acc, r) => ({
      total: acc.total + Number(r.total ?? 0),
      unhealthy: acc.unhealthy + Number(r.unhealthy ?? 0),
      healthy: acc.healthy + Number(r.healthy ?? 0),
    }),
    { total: 0, unhealthy: 0, healthy: 0 },
  );
  evidence.push(ev('resourcegraph.defender_assessments', { ...totals, by_subscription: assess.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.mla.evc.defender_assessments_running', passed: totals.total > 0, severity: 'high',
    current: {
      summary: totals.total > 0
        ? `${totals.total} Defender for Cloud security assessment(s) — ${totals.unhealthy} unhealthy, ${totals.healthy} healthy. Configuration evaluation is actively running.`
        : 'No Microsoft Defender for Cloud assessments — configuration evaluation is not generating any evidence.',
      observations: { ...totals },
    },
    target: {
      summary: 'Microsoft Defender for Cloud is enabled and producing assessment evidence (`microsoft.security/assessments` is non-empty).',
      rationale: 'NIST CA-7, CM-6, CM-7, RA-5. FedRAMP requires continuous configuration evaluation.',
    },
    gap: { description: 'Defender for Cloud assessments are absent — configuration drift / mis-configurations are not being detected automatically.', affected_resources: [{ type: 'azure_defender_assessment', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Enable Defender for Cloud (Standard tier where appropriate) on every in-scope subscription; the built-in Microsoft Cloud Security Benchmark assessments will start producing evidence within minutes.',
      options: [
        { approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az security pricing create -n VirtualMachines --tier Standard', 'az security pricing create -n StorageAccounts --tier Standard', 'Wait ~10 minutes for the first assessment scan'] },
      ],
    },
    nist_controls: ['ca-7', 'cm-6', 'ra-5'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'Both rely on Defender / Azure Policy being enabled.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-INR-RIR — Reviewing Incident Response Procedures (HYBRID)
// Azure proxy: at least one Action Group exists (the Azure Monitor canonical
// "where do alerts go" primitive — wraps email / webhook / PagerDuty / ITSM
// / Logic-App / Function / EventHub receivers). Sentinel automation rules
// count too, as a higher-level orchestration signal.
//
// The deep IR runbook + last-procedure-review minutes stay as process
// artifacts in ksi-map.ts.
// =====================================================================
export async function collectInrRir(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Azure Monitor Action Groups.
  const actionGroups = await runKql(subs,
    'Resources | where type =~ "microsoft.insights/actiongroups" ' +
    '| extend receivers = properties.emailReceivers, smsReceivers = properties.smsReceivers, ' +
    'webhookReceivers = properties.webhookReceivers, logicAppReceivers = properties.logicAppReceivers, ' +
    'azureFunctionReceivers = properties.azureFunctionReceivers, eventHubReceivers = properties.eventHubReceivers ' +
    '| project id, name, subscriptionId, location, ' +
    'email_count = array_length(receivers), sms_count = array_length(smsReceivers), ' +
    'webhook_count = array_length(webhookReceivers), logic_app_count = array_length(logicAppReceivers), ' +
    'function_count = array_length(azureFunctionReceivers), eventhub_count = array_length(eventHubReceivers)');
  if (actionGroups.error) warnings.push(actionGroups.error);

  // 2) Sentinel automation rules — bonus signal (do not require, but record).
  const automationRules = await runKql(subs,
    'Resources | where type =~ "microsoft.securityinsights/automationrules" ' +
    '| project id, name, subscriptionId');
  if (automationRules.error) warnings.push(automationRules.error);

  evidence.push(ev('resourcegraph.action_groups', {
    total: actionGroups.rows.length,
    sample: actionGroups.rows.slice(0, 20),
  }));
  evidence.push(ev('resourcegraph.sentinel_automation_rules', {
    total: automationRules.rows.length,
    sample: automationRules.rows.slice(0, 10),
  }));

  // Receivers-per-action-group breakdown: we want at least one Action Group
  // that points somewhere off-Azure (webhook/Logic App/Function/EventHub/SMS)
  // OR has email receivers. A vacant Action Group is plumbing-without-routing.
  const populatedActionGroups = actionGroups.rows.filter((g: any) => {
    return Number(g.email_count ?? 0) + Number(g.sms_count ?? 0) + Number(g.webhook_count ?? 0)
      + Number(g.logic_app_count ?? 0) + Number(g.function_count ?? 0) + Number(g.eventhub_count ?? 0) > 0;
  }).length;

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'PagerDuty / OpsGenie via Action Group webhook or ITSM receiver',
      description: 'Action Groups commonly route alerts to a 3rd-party paging platform via webhook / ITSM connector.',
      evidence_required: ['Action Group webhook URL (redacted)', 'Sample paging event from the vendor', 'Runbook URL'],
      detected: false, detection_signals: [],
    },
    {
      via: 'Sentinel automation rules + Logic Apps playbooks',
      description: 'Sentinel automation rules run Logic-App playbooks as response orchestration.',
      evidence_required: ['Automation rule export', 'Playbook run history'],
      detected: automationRules.rows.length > 0,
      detection_signals: automationRules.rows.length > 0 ? [`${automationRules.rows.length} automation rule(s) detected via Resource Graph`] : [],
    },
  ];

  findings.push(finding({
    rule: 'azure.inr.rir.alert_routing_plumbing_present',
    passed: populatedActionGroups >= 1 || automationRules.rows.length >= 1,
    severity: 'high',
    current: {
      summary: (populatedActionGroups >= 1 || automationRules.rows.length >= 1)
        ? `${actionGroups.rows.length} Action Group(s) (${populatedActionGroups} with at least one receiver) and ${automationRules.rows.length} Sentinel automation rule(s) — alert routing is wired.`
        : (actionGroups.rows.length > 0
          ? `${actionGroups.rows.length} Action Group(s) exist but none have any receiver wired — plumbing without routing.`
          : 'No Azure Monitor Action Groups or Sentinel automation rules — alerts are not being routed anywhere.'),
      observations: {
        action_groups_total: actionGroups.rows.length,
        action_groups_with_receivers: populatedActionGroups,
        sentinel_automation_rules: automationRules.rows.length,
      },
    },
    target: { summary: 'At least one Azure Monitor Action Group with a populated receiver list (email / webhook / Logic App / Function / EventHub) OR a Sentinel automation rule exists.', rationale: 'NIST IR-4, IR-4(1). IR procedures need a routing fabric — Action Groups are the Azure-canonical primitive.' },
    gap: { description: 'Without alert routing, IR procedures are manual / nobody gets paged.', affected_resources: [{ type: 'azure_monitor_action_group', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Provision an Action Group bound to email + a webhook to the incident-management platform (PagerDuty / OpsGenie / ServiceNow).',
      options: [
        { approach: 'Terraform azurerm_monitor_action_group with email + webhook receiver.', mechanism: 'terraform', steps: [
          'Declare azurerm_monitor_action_group with email_receiver { ... } and webhook_receiver { ... }',
          'Reference the Action Group from azurerm_monitor_metric_alert / scheduled_query_rules_alert',
          'Send a test event; confirm it lands in the paging platform',
        ] },
        { approach: 'Sentinel automation rule wired to a Logic-App playbook.', mechanism: 'console', steps: [
          'Sentinel → Automation → New automation rule',
          'Trigger: when a Sentinel incident is created',
          'Action: run playbook (Logic App) that pages on-call',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ir-4', 'ir-4.1'],
    cross_ksi_dependencies: [
      { ksi_id: 'KSI-IAM-SUS', relationship: 'shares-remediation', note: 'IAM-SUS covers IAM-specific alerts; INR-RIR is the broader routing fabric.' },
      { ksi_id: 'KSI-MLA-OSM', relationship: 'depends-on', note: 'Sentinel SIEM is the upstream signal generator the action groups route from.' },
    ],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
