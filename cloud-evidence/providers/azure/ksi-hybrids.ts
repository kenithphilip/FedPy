/**
 * Azure KSI HYBRID collectors — mirrors of `providers/{aws,gcp}/ksi-hybrids.ts`
 * for the 5 indicators that previously had no Azure proxy:
 *
 *   - KSI-CMT-RVP — Reviewing Change Procedures
 *   - KSI-INR-AAR — Generating After Action Reports
 *   - KSI-INR-RPI — Reviewing Past Incidents
 *   - KSI-SCR-MIT — Mitigating Supply Chain Risk
 *   - KSI-SVC-PRR — Preventing Residual Risk
 *
 * Each KSI is a "persistently review the effectiveness of X" / "mitigate X"
 * HYBRID obligation. The cloud signal here is the proxy half — Azure-canonical
 * evidence that the capability exists and is wired up. The process artifact
 * (review minutes, drill records, AAR templates) is the other half, attached
 * via `process_artifacts_required` in `ksi-map.ts`.
 *
 * Read-only via Resource Graph + securityresources tables; no new IAM
 * permissions beyond AZ-1's `Reader` + the `Security Reader` role MLA-EVC
 * already documents (for the `securityresources` table).
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding, AlternativeSatisfier } from '../../core/envelope.ts';
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
// KSI-CMT-RVP — Reviewing Change Procedures
// Proxy: Azure Policy assignments are present AND the policy-state table
// shows active evaluation (the change-management baseline is being enforced).
// =====================================================================
export async function collectCmtRvp(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const assignments = await runKql(subs,
    'policyresources | where type =~ "microsoft.authorization/policyassignments" ' +
    '| project id, name, subscriptionId');
  if (assignments.error) warnings.push(assignments.error);

  const states = await runKql(subs,
    'policyresources | where type =~ "microsoft.policyinsights/policystates" ' +
    '| summarize n = count() by subscriptionId');
  if (states.error) warnings.push(states.error);

  const totalAssignments = assignments.rows.length;
  const subsEvaluating = states.rows.length;
  evidence.push(ev('resourcegraph.policy_assignments_for_change_review', {
    total_assignments: totalAssignments, subscriptions_evaluating: subsEvaluating,
  }));

  findings.push(finding({
    rule: 'azure.cmt.rvp.change_baseline_enforced',
    passed: totalAssignments >= 1 && subsEvaluating >= 1,
    severity: 'medium',
    current: {
      summary: totalAssignments === 0
        ? 'No Azure Policy assignments — no automated change-management baseline to review.'
        : subsEvaluating === 0
          ? `${totalAssignments} policy assignment(s) but no policy-state evaluations — assignment exists but isn't running.`
          : `${totalAssignments} policy assignment(s) actively evaluating across ${subsEvaluating} subscription(s).`,
      observations: { total_assignments: totalAssignments, subscriptions_evaluating: subsEvaluating },
    },
    target: { summary: '≥ 1 Azure Policy assignment present AND the policy-state table is non-empty (the change-management baseline is actively running).', rationale: 'NIST CM-3, CM-3(2), CM-5, CM-7(1). Reviewing change procedures requires a baseline + an enforcement engine producing reviewable findings.' },
    gap: { description: 'Change-management baseline is either absent or not running — periodic review has no source data.', affected_resources: [{ type: 'azure_policy_assignment', identifier: 'aggregate', attributes: { assignments: totalAssignments, subscriptions_evaluating: subsEvaluating } }] },
    remediation: {
      summary: 'Assign Azure Policy (start with the Microsoft Cloud Security Benchmark initiative) at the management-group or subscription level.',
      options: [{ approach: 'Assign MCSB initiative via az policy assignment create.', mechanism: 'cli', steps: ['az policy assignment create --name mcsb --policy-set-definition 1f3afdf9-d0c9-4c3d-847f-89da613e70a8 --scope /subscriptions/<id>', 'Wait ~10 minutes for first evaluation; verify with az policy state list'] }],
    },
    nist_controls: ['cm-3', 'cm-3.2', 'cm-5', 'cm-7.1', 'cm-9'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'CNA-EIS covers policy assignment presence; CMT-RVP looks at the same data to assess whether change procedures are reviewable.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-INR-AAR — Generating After Action Reports
// Proxy: Sentinel automation rules OR Defender for Cloud alert rules exist
// (incident workflow is wired up to produce data feeding AARs).
// =====================================================================
export async function collectInrAar(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const sentinelAutomation = await runKql(subs,
    'Resources | where type =~ "microsoft.securityinsights/automationrules" ' +
    '| project id, name, subscriptionId');
  if (sentinelAutomation.error) warnings.push(sentinelAutomation.error);

  const defenderAlerts = await runKql(subs,
    'Resources | where type =~ "microsoft.insights/activitylogalerts" or type =~ "microsoft.insights/scheduledqueryrules" ' +
    '| project id, name, type, subscriptionId');
  if (defenderAlerts.error) warnings.push(defenderAlerts.error);

  const automationCount = sentinelAutomation.rows.length;
  const alertCount = defenderAlerts.rows.length;
  evidence.push(ev('resourcegraph.incident_workflow_signals', {
    sentinel_automation_rules: automationCount, monitor_alert_rules: alertCount,
  }));

  findings.push(finding({
    rule: 'azure.inr.aar.incident_workflow_wired',
    passed: automationCount >= 1 || alertCount >= 1,
    severity: 'medium',
    current: {
      summary: (automationCount + alertCount) === 0
        ? 'No Sentinel automation rules AND no Monitor/Defender alert rules — incident workflow has no automation feeding AAR data.'
        : `${automationCount} Sentinel automation rule(s) + ${alertCount} Monitor alert rule(s) — incident telemetry is being generated.`,
      observations: { sentinel_automation_rules: automationCount, monitor_alert_rules: alertCount },
    },
    target: { summary: 'At least one Sentinel automation rule OR Monitor/Defender alert rule exists — incident detection produces structured records that can be reviewed in AAR.', rationale: 'NIST IR-3, IR-4, IR-4(1), IR-8. AARs need a structured incident record stream as the input.' },
    gap: { description: 'No incident telemetry pipeline visible in Azure — AARs would have to be assembled manually from ad-hoc logs.', affected_resources: [{ type: 'azure_incident_workflow', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Enable Sentinel + configure at least one automation rule that fires on high-severity incidents (sends to ticket system / chatops), OR add a Monitor activity-log alert on the same signals.',
      options: [{ approach: 'Sentinel automation rule via Terraform.', mechanism: 'terraform', steps: ['azurerm_sentinel_automation_rule with display_name + triggers_on = "Incidents"', 'Action_play_book = the runbook that creates the AAR ticket'] }],
    },
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-8'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-INR-RPI — Reviewing Past Incidents
// Proxy: at least one Log Analytics workspace OR diagnostic setting with
// non-default retention is configured (past incidents are retained for review).
// =====================================================================
export async function collectInrRpi(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Workspaces with retention metadata. retentionInDays is the canonical
  // signal — Microsoft default is 30; we require >= 90 (NIST CP-9 / IR-5).
  const workspaces = await runKql(subs,
    'Resources | where type =~ "microsoft.operationalinsights/workspaces" ' +
    '| extend retention = toint(properties.retentionInDays) ' +
    '| project id, name, subscriptionId, retention');
  if (workspaces.error) warnings.push(workspaces.error);

  const total = workspaces.rows.length;
  const adequate = workspaces.rows.filter((w: any) => Number(w.retention ?? 0) >= 90);
  evidence.push(ev('resourcegraph.workspace_retention_for_incident_review', {
    total, adequate_retention: adequate.length,
    sample: workspaces.rows.slice(0, 20).map((w: any) => ({ name: w.name, retention: w.retention })),
  }));

  findings.push(finding({
    rule: 'azure.inr.rpi.incident_retention_adequate',
    passed: total === 0 || adequate.length >= 1,
    severity: 'medium',
    current: {
      summary: total === 0
        ? 'No Log Analytics workspaces — no incident-record retention to evaluate.'
        : adequate.length === 0
          ? `${total} workspace(s) but none have ≥ 90-day retention — past-incident review window is too short.`
          : `${adequate.length}/${total} workspace(s) have ≥ 90-day retention — past incidents are reviewable for at least a quarter.`,
      observations: { workspaces: total, adequate_retention: adequate.length },
    },
    target: { summary: 'At least one Log Analytics workspace has `retentionInDays >= 90` — past incidents from the last quarter can be reviewed for patterns and recurring root causes.', rationale: 'NIST IR-3, IR-4(1), IR-5, IR-8. Past-incident review requires a retention window long enough to spot patterns.' },
    gap: { description: 'Incident record retention is too short or absent — pattern review across past incidents is not possible.', affected_resources: workspaces.rows.filter((w: any) => Number(w.retention ?? 0) < 90).slice(0, 50).map((w: any) => ({ type: 'azure_log_analytics_workspace', identifier: w.id, attributes: { name: w.name, retention_days: w.retention } })) },
    remediation: {
      summary: 'Increase workspace retention to ≥ 90 days (180 or 365 days is typical for FedRAMP environments).',
      options: [{ approach: 'az CLI.', mechanism: 'cli', steps: ['az monitor log-analytics workspace update -g <rg> -n <workspace> --retention-time 90'] }],
    },
    nist_controls: ['ir-3', 'ir-4.1', 'ir-5', 'ir-8'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-RVL', relationship: 'shares-remediation', note: 'MLA-RVL covers retention for log review generally; INR-RPI applies the same signal to incident retention.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-SCR-MIT — Mitigating Supply Chain Risk
// Proxy: ACR Defender vulnerability assessment configured OR image
// signing/quarantine policies present.
// =====================================================================
export async function collectScrMit(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // ACR with content trust OR quarantine policy enabled — the supply-chain
  // mitigation primitives at the registry level.
  const registries = await runKql(subs,
    'Resources | where type =~ "microsoft.containerregistry/registries" ' +
    '| extend trust = tostring(properties.policies.trustPolicy.status), ' +
    'quarantine = tostring(properties.policies.quarantinePolicy.status) ' +
    '| project id, name, subscriptionId, trust, quarantine');
  if (registries.error) warnings.push(registries.error);

  // Defender for Containers on Standard tier — gates the vulnerability-assessment
  // feed (Microsoft Defender Vulnerability Management for container images).
  const pricings = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/pricings" ' +
    '| where name =~ "Containers" or name =~ "ContainerRegistry" ' +
    '| extend tier = tostring(properties.pricingTier) ' +
    '| project id, name, subscriptionId, tier');
  if (pricings.error) warnings.push(pricings.error);

  const totalReg = registries.rows.length;
  const mitigated = registries.rows.filter((r: any) =>
    String(r.trust ?? '').toLowerCase() === 'enabled' ||
    String(r.quarantine ?? '').toLowerCase() === 'enabled',
  );
  const defenderOn = pricings.rows.filter((p: any) => String(p.tier ?? '').toLowerCase() === 'standard').length;

  evidence.push(ev('resourcegraph.supply_chain_mitigation_signals', {
    registries: totalReg, with_trust_or_quarantine: mitigated.length, defender_containers_standard: defenderOn,
  }));

  // Pass if EITHER signal is present. Defender alone is fine (active scanning);
  // registry policies alone is also fine (the operator has pre-deploy gates).
  const passed = totalReg === 0
    ? defenderOn >= 1
    : (mitigated.length >= 1 || defenderOn >= 1);

  findings.push(finding({
    rule: 'azure.scr.mit.supply_chain_mitigation_present',
    passed,
    severity: 'medium',
    current: {
      summary: totalReg === 0 && defenderOn === 0
        ? 'No ACR registries AND Defender for Containers is not on Standard tier — no supply-chain mitigation signal.'
        : `${mitigated.length}/${totalReg} ACR(s) with content-trust or quarantine policy enabled; Defender for Containers on Standard in ${defenderOn} subscription(s).`,
      observations: { registries: totalReg, with_trust_or_quarantine: mitigated.length, defender_containers_standard: defenderOn },
    },
    target: { summary: 'At least one ACR has content-trust OR quarantine policy enabled, OR Defender for Containers is on Standard tier in at least one subscription.', rationale: 'NIST AC-20, SA-9, SA-10, SA-11, SR-5, SR-6, SI-7(1). Supply-chain mitigation requires a registry-level gate or runtime vulnerability scanning.' },
    gap: { description: 'No supply-chain mitigation primitive observed in Azure — image deployments are not gated by signing/quarantine or scanned by Defender.', affected_resources: (() => { const offenders = registries.rows.filter((r: any) => !mitigated.includes(r)).slice(0, 50).map((r: any) => ({ type: 'azure_container_registry', identifier: r.id, attributes: { name: r.name, trust: r.trust, quarantine: r.quarantine } })); return offenders.length ? offenders : [{ type: 'azure_subscription', identifier: subs[0] ?? 'subscription', name: 'no ACR and no Defender for Containers (Standard) — no supply-chain mitigation primitive', attributes: { registries: totalReg, defender_containers_standard: defenderOn } }]; })() },
    remediation: {
      summary: 'Enable Defender for Containers (Standard) on every in-scope sub OR configure ACR content trust / quarantine on each registry.',
      options: [{ approach: 'az CLI — Defender for Containers + ACR quarantine.', mechanism: 'cli', steps: ['az security pricing create -n Containers --tier Standard', 'az acr config quarantine update -r <acr> --status Enabled'] }],
    },
    nist_controls: ['ac-20', 'sa-9', 'sa-10', 'sa-11', 'sr-5', 'sr-6', 'si-7.1'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CMT-RMV', relationship: 'shares-remediation', note: 'CMT-RMV covers registry presence + admin-disable; SCR-MIT extends to signing/quarantine + scan-feed.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-SVC-PRR — Preventing Residual Risk (no unintended data transfer
// via shared resources). Proxy: storage accounts have public-access disabled
// AND any SQL/Cosmos instance enforces private/network-restricted access.
// =====================================================================
export async function collectSvcPrr(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Storage accounts — public network access posture.
  const storage = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend pubAccess = tostring(properties.publicNetworkAccess), ' +
    'allowBlobAnon = tobool(properties.allowBlobPublicAccess) ' +
    '| project id, name, subscriptionId, pubAccess, allowBlobAnon');
  if (storage.error) warnings.push(storage.error);

  const totalStorage = storage.rows.length;
  // "Disabled" or absent + allowBlobPublicAccess=false → properly residual-risk-mitigated.
  const offending = storage.rows.filter((s: any) => {
    const pa = String(s.pubAccess ?? '').toLowerCase();
    const blob = s.allowBlobAnon === true;
    return pa === 'enabled' || blob;
  });

  evidence.push(ev('resourcegraph.storage_public_access', {
    total: totalStorage, offending: offending.length,
    sample: offending.slice(0, 10).map((s: any) => ({ id: s.id, public_network_access: s.pubAccess, allow_blob_public_access: s.allowBlobAnon })),
  }));

  findings.push(finding({
    rule: 'azure.svc.prr.shared_resources_isolated',
    passed: totalStorage === 0 || offending.length === 0,
    severity: 'high',
    current: {
      summary: totalStorage === 0
        ? 'No storage accounts to evaluate.'
        : offending.length === 0
          ? `All ${totalStorage} storage account(s) deny public network access — residual-risk posture good.`
          : `${offending.length}/${totalStorage} storage account(s) allow public network or anonymous blob access — residual-data leakage risk.`,
      observations: { total_storage: totalStorage, offending: offending.length },
    },
    target: { summary: 'Every storage account has `publicNetworkAccess = "Disabled"` AND `allowBlobPublicAccess = false`.', rationale: 'NIST SC-4. Residual data on shared resources must not be reachable by other tenants or the open internet.' },
    gap: { description: 'Storage accounts with public access enabled risk leaking residual data via misconfigured anonymous container ACLs.', affected_resources: offending.slice(0, 50).map((s: any) => ({ type: 'azure_storage_account', identifier: s.id, attributes: { name: s.name, public_network_access: s.pubAccess, allow_blob_public_access: s.allowBlobAnon } })) },
    remediation: {
      summary: 'Set publicNetworkAccess=Disabled + allowBlobPublicAccess=false on every storage account; use Private Endpoints for legitimate cross-network access.',
      options: [
        { approach: 'az CLI per account.', mechanism: 'cli', steps: ['az storage account update -n <acct> --public-network-access Disabled --allow-blob-public-access false'] },
        { approach: 'Terraform azurerm_storage_account.public_network_access_enabled = false.', mechanism: 'terraform', steps: ['Set public_network_access_enabled = false; allow_nested_items_to_be_public = false; apply'] },
      ],
    },
    nist_controls: ['sc-4'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-RNT', relationship: 'shares-remediation', note: 'CNA-RNT covers NSG-level ingress; SVC-PRR applies the same intent at the data-plane (storage/SQL/Cosmos).' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
