/**
 * Azure config + policy KSI collectors.
 *
 *   - KSI-CNA-EIS — Enforcing Intended State. Azure Policy is assigned at the
 *     management-group / subscription level and is **actively evaluating** the
 *     environment (the policy-state table is non-empty).
 *   - KSI-CNA-IBP — Implementing Best Practices. The Microsoft Cloud Security
 *     Benchmark (MCSB) initiative is assigned (its built-in id is stable across
 *     tenants — Microsoft's own FedRAMP/NIST-aligned baseline).
 *
 * Both via Azure Resource Graph `policyresources` table — no new permissions
 * beyond AZ-1's Reader role.
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

/**
 * Microsoft Cloud Security Benchmark (MCSB) — the built-in policy initiative
 * Microsoft maintains as the recommended security baseline. Its policy-set
 * definition id is stable across tenants (Azure product constant). MCSB is the
 * single best signal that the operator has adopted Microsoft's published best
 * practices, which themselves map to FedRAMP/NIST control families.
 */
const MCSB_INITIATIVE_ID = '/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8';

// Built-in regulatory-compliance initiative ids that signal FedRAMP / NIST
// adoption (the operator has explicitly opted into a FedRAMP-aligned baseline,
// not just the generic MCSB). Each value is the policy-set-definition resource
// id (lowercase comparison).
const REGULATORY_INITIATIVE_PATTERNS = [
  /fedramp.?(moderate|high)/i,
  /nist.?sp.?800.?53/i,
  /nist.?sp.?800.?171/i,
];

// =====================================================================
// KSI-CNA-EIS — Enforcing Intended State
// =====================================================================
export async function collectCnaEis(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Policy assignments present.
  const pa = await runKql(subs,
    'policyresources | where type =~ "microsoft.authorization/policyassignments" ' +
    '| extend scope = tostring(properties.scope), displayName = tostring(properties.displayName) ' +
    '| project id, subscriptionId, name, displayName, scope');
  if (pa.error) warnings.push(pa.error);
  evidence.push(ev('resourcegraph.policy_assignments', { count: pa.rows.length, sample: pa.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.cna.eis.policy_assignments_present', passed: pa.rows.length > 0, severity: 'high',
    current: {
      summary: pa.rows.length > 0
        ? `${pa.rows.length} Azure Policy assignment(s) in scope — automated config-evaluation infrastructure is in place.`
        : 'No Azure Policy assignments — there is no automated configuration evaluation running on the tenant.',
      observations: { count: pa.rows.length },
    },
    target: {
      summary: 'At least one Azure Policy assignment exists at MG / subscription / RG scope. Without an assignment, no automated config-evaluation can run.',
      rationale: 'NIST CA-2(1), CA-7(1), CM-6, CM-7. FedRAMP requires automated configuration assessment.',
    },
    gap: { description: 'No Azure Policy assignment is present, so policy compliance cannot be evaluated.', affected_resources: [{ type: 'azure_policy_assignment', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Assign at least the Microsoft Cloud Security Benchmark initiative at the management-group scope; run a remediation task to backfill.',
      options: [{ approach: 'Console.', mechanism: 'console', steps: ['Policy → Definitions → search "Microsoft cloud security benchmark"', 'Assign at MG scope', 'Run remediation task'] }],
    },
    nist_controls: ['ca-2.1', 'ca-7.1', 'cm-6'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-IBP', relationship: 'shares-remediation', note: 'The MCSB initiative satisfies both KSIs.' }],
  }));

  // 2) Policy-state evaluations actively running (policystates rows exist).
  const ps = await runKql(subs,
    'policyresources | where type =~ "microsoft.policyinsights/policystates" ' +
    '| summarize total = count(), nonCompliant = countif(tostring(properties.complianceState) == "NonCompliant") by subscriptionId');
  if (ps.error) warnings.push(ps.error);
  const totalStates = ps.rows.reduce((a, r) => a + Number(r.total ?? 0), 0);
  const totalNonCompliant = ps.rows.reduce((a, r) => a + Number(r.nonCompliant ?? 0), 0);
  evidence.push(ev('resourcegraph.policy_states', { total: totalStates, non_compliant: totalNonCompliant, by_sub: ps.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.cna.eis.policy_evaluations_running', passed: totalStates > 0, severity: 'medium',
    current: {
      summary: totalStates > 0
        ? `${totalStates} policy-state evaluation(s) recorded — Azure Policy is actively scanning the tenancy (${totalNonCompliant} non-compliant).`
        : 'No policy-state evaluations found — Azure Policy assignments may exist but evaluations have not run (or RBAC blocks reading the state table).',
      observations: { total: totalStates, non_compliant: totalNonCompliant },
    },
    target: { summary: 'The `microsoft.policyinsights/policystates` table is non-empty — Azure Policy is actively evaluating in-scope resources.', rationale: 'NIST CA-7(1), CM-6, CM-7. Continuous monitoring.' },
    gap: { description: 'Azure Policy has no recent state evaluations. Either no assignments exist (see the first finding) or the policy engine has not yet evaluated resources.', affected_resources: [{ type: 'azure_policy_state', identifier: 'none', attributes: {} }] },
    remediation: { summary: 'After assignment, trigger a manual policy-compliance scan to populate the state table.', options: [{ approach: 'az CLI.', mechanism: 'cli', steps: ['az policy state trigger-scan --resource-group <rg>  # OR for the subscription, omit --resource-group'] }] },
    nist_controls: ['ca-7.1', 'cm-6'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CNA-IBP — Implementing Best Practices
// =====================================================================
export async function collectCnaIbp(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Microsoft Cloud Security Benchmark initiative assigned.
  const mcsb = await runKql(subs,
    'policyresources | where type =~ "microsoft.authorization/policyassignments" ' +
    '| extend defId = tolower(tostring(properties.policyDefinitionId)) ' +
    `| where defId == tolower("${MCSB_INITIATIVE_ID}") ` +
    '| project id, subscriptionId, name, displayName=tostring(properties.displayName), scope=tostring(properties.scope)');
  if (mcsb.error) warnings.push(mcsb.error);
  evidence.push(ev('resourcegraph.mcsb_assignment', { count: mcsb.rows.length, sample: mcsb.rows.slice(0, 10) }));

  findings.push(finding({
    rule: 'azure.cna.ibp.mcsb_assigned', passed: mcsb.rows.length > 0, severity: 'high',
    current: {
      summary: mcsb.rows.length > 0
        ? `${mcsb.rows.length} Microsoft Cloud Security Benchmark assignment(s) — Microsoft's recommended baseline is enforced.`
        : 'Microsoft Cloud Security Benchmark (MCSB) is not assigned — Microsoft\'s own published security baseline isn\'t being evaluated.',
      observations: { count: mcsb.rows.length },
    },
    target: {
      summary: 'The Microsoft Cloud Security Benchmark policy initiative is assigned at the management-group (or subscription) scope.',
      rationale: 'NIST CM-6, CM-7, SA-8. MCSB is the FedRAMP-aligned Microsoft best-practice baseline.',
    },
    gap: { description: 'The Microsoft Cloud Security Benchmark initiative is not assigned anywhere visible to this runner.', affected_resources: [{ type: 'azure_policy_initiative', identifier: 'microsoft-cloud-security-benchmark', attributes: {} }] },
    remediation: {
      summary: 'Assign MCSB at the management-group (root) scope; turn on automatic remediation tasks where supported.',
      options: [
        { approach: 'Azure Portal.', mechanism: 'console', steps: ['Policy → Definitions → search "Microsoft cloud security benchmark"', 'Assign → Management group → root', 'Create remediation tasks for the DINE policies'] },
        { approach: 'Terraform azurerm_management_group_policy_assignment.', mechanism: 'terraform', steps: ['policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8"', 'identity { type = "SystemAssigned" }  # for DINE remediation'] },
      ],
    },
    nist_controls: ['cm-6', 'cm-7', 'sa-8'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'Assigning MCSB satisfies the EIS "any assignment present" requirement too.' }],
  }));

  // 2) Regulatory-compliance baseline assignment (NIST 800-53 / FedRAMP) — a
  // stronger signal that the operator has *explicitly* opted into FedRAMP.
  const reg = await runKql(subs,
    'policyresources | where type =~ "microsoft.authorization/policyassignments" ' +
    '| extend dn = tostring(properties.displayName), defId = tostring(properties.policyDefinitionId) ' +
    '| project id, subscriptionId, name, dn, defId');
  if (reg.error) warnings.push(reg.error);
  const regulatoryHits = reg.rows.filter((r) => {
    const blob = `${r.dn ?? ''} ${r.defId ?? ''}`;
    return REGULATORY_INITIATIVE_PATTERNS.some((pat) => pat.test(blob));
  });
  evidence.push(ev('resourcegraph.regulatory_initiatives', {
    matched: regulatoryHits.length,
    sample: regulatoryHits.slice(0, 10),
  }));

  findings.push(finding({
    rule: 'azure.cna.ibp.regulatory_initiative_assigned', passed: regulatoryHits.length > 0, severity: 'medium',
    current: {
      summary: regulatoryHits.length > 0
        ? `${regulatoryHits.length} regulatory-compliance initiative assignment(s) matching FedRAMP / NIST patterns.`
        : 'No FedRAMP / NIST 800-53 / NIST 800-171 regulatory-compliance initiative assigned.',
      observations: { matched: regulatoryHits.length, sample: regulatoryHits.slice(0, 10) },
    },
    target: {
      summary: 'A FedRAMP-aligned regulatory-compliance initiative (FedRAMP Moderate/High or NIST SP 800-53/171) is assigned, in addition to the MCSB baseline.',
      rationale: 'NIST CA-2, CM-6, SA-8. FedRAMP-aligned baselines explicitly evaluate the controls relevant to the authorization package.',
    },
    gap: { description: 'No explicit FedRAMP / NIST regulatory initiative is assigned. MCSB is a strong baseline, but the FedRAMP-specific initiative gives compliance-state evidence keyed to the actual controls.', affected_resources: [{ type: 'azure_policy_initiative', identifier: 'fedramp-or-nist', attributes: {} }] },
    remediation: {
      summary: 'Assign the FedRAMP Moderate / High built-in initiative at the management-group scope, alongside MCSB.',
      options: [{ approach: 'Console.', mechanism: 'console', steps: ['Policy → Definitions → built-in → search "FedRAMP"', 'Pick the impact tier matching the authorization', 'Assign at MG scope; enable compliance evaluation'] }],
    },
    nist_controls: ['ca-2', 'cm-6', 'sa-8'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-CNA-DFP — Defining Functionality and Privileges
// =====================================================================
/**
 * The strongest automatable signal we have for "narrow functionality and
 * privileges" in Entra ID / ARM is the presence of CUSTOM role definitions —
 * operators that need least-privilege beyond the built-in roles have authored
 * their own. We DON'T count built-in roles here (they exist by default and
 * say nothing about operator intent).
 */
export async function collectCnaDfp(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const roles = await runKql(subs,
    'authorizationresources | where type =~ "microsoft.authorization/roledefinitions" ' +
    '| extend roleType = tostring(properties.type), roleName = tostring(properties.roleName) ' +
    '| where roleType == "CustomRole" ' +
    '| project id, name, roleName, subscriptionId');
  if (roles.error) warnings.push(roles.error);
  evidence.push(ev('resourcegraph.custom_role_definitions', { count: roles.rows.length, sample: roles.rows.slice(0, 20) }));

  findings.push(finding({
    rule: 'azure.cna.dfp.custom_role_definitions_present', passed: roles.rows.length > 0, severity: 'medium',
    current: {
      summary: roles.rows.length > 0
        ? `${roles.rows.length} custom RBAC role definition(s) — operators define narrow least-privilege roles instead of relying on built-ins alone.`
        : 'No custom RBAC role definitions found — every grant relies on Azure built-in roles, which are typically broader than necessary.',
      observations: { count: roles.rows.length, sample: roles.rows.slice(0, 10).map((r) => r.roleName) },
    },
    target: {
      summary: 'At least one custom RBAC role definition exists — narrow, function-specific permissions instead of blanket Owner / Contributor / Reader.',
      rationale: 'NIST AC-3, AC-6, AC-6(1), CM-7. Built-in roles are necessarily broad; custom roles are the canonical Azure mechanism for least privilege at the resource level.',
    },
    gap: { description: 'No custom roles defined — least-privilege is constrained by the granularity of Azure built-ins.', affected_resources: [{ type: 'azure_role_definition', identifier: 'custom-roles', attributes: {} }] },
    remediation: {
      summary: 'Author one or more custom roles scoped to the specific actions your workloads need; use Azure Resource Manager templates / Terraform for reproducibility.',
      options: [
        { approach: 'Terraform azurerm_role_definition.', mechanism: 'terraform', steps: ['Identify the exact actions a workload needs (e.g. Microsoft.Storage/storageAccounts/listKeys/action)', 'Author a custom role scoped to those actions only', 'Assign the custom role; remove the broader built-in grant'] },
      ],
    },
    nist_controls: ['ac-3', 'ac-6', 'ac-6.1', 'cm-7'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Custom roles reduce reliance on Global Admin / built-in Owner.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
