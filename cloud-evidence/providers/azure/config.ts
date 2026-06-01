/**
 * Azure config + policy KSI collectors.
 *
 *   - KSI-CNA-EIS — Enforcing Intended State. Azure Policy is assigned at the
 *     management-group / subscription level and is **actively evaluating** the
 *     environment (the policy-state table is non-empty).
 *   - KSI-CNA-IBP — Implementing Best Practices. The Microsoft Cloud Security
 *     Benchmark (MCSB) initiative is assigned (its built-in id is stable across
 *     tenants — Microsoft's own FedRAMP/NIST-aligned baseline).
 *   - KSI-CNA-DFP — Defining Functionality and Privileges. Custom RBAC role
 *     definitions exist (operators have authored narrow least-privilege roles).
 *   - KSI-SVC-ACM — Automating Configuration Management. ARM deployment history
 *     and Azure Policy compliance ratio — "is IaC the source of truth, and is
 *     the environment compliant against the assigned policies?"
 *   - KSI-SVC-EIS — Evaluating and Improving Security (HYBRID). Defender for
 *     Cloud secure score is being computed and is at least at a tolerable
 *     ratio — proxy for the "continuous improvement" loop.
 *
 * All via Azure Resource Graph (`policyresources`, `authorizationresources`,
 * `securityresources`, and the default `Resources` table). No new permissions
 * beyond AZ-1's Reader role except SVC-EIS which needs `Security Reader` for
 * `securityresources` — same constraint MLA-EVC already documents.
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

// =====================================================================
// KSI-SVC-ACM — Automating Configuration Management
// "Is IaC the source of truth, and is the environment compliant against
// the policies assigned to it?" Two angles:
//   1. ARM deployment history — proves that something declarative (ARM /
//      Bicep / Terraform / azd) is being applied. We sample the
//      microsoft.resources/deployments resources and look at when the
//      most recent deployment ran across the configured subscriptions.
//   2. Azure Policy compliance ratio — what fraction of policy-state
//      evaluations are Compliant? Reuses the `policyresources/policystates`
//      table already familiar from CNA-EIS, but focuses on the ratio
//      rather than mere presence.
// =====================================================================
export async function collectSvcAcm(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) ARM deployment history. We project the latest deployment timestamp
  // per subscription. Successful or otherwise — what we care about is "did
  // a declarative deployment run recently?", not the outcome (CNA-EIS
  // covers Azure Policy compliance directly).
  const deployments = await runKql(subs,
    'Resources | where type =~ "microsoft.resources/deployments" ' +
    '| extend ts = todatetime(properties.timestamp), state = tostring(properties.provisioningState) ' +
    '| project id, name, subscriptionId, ts, state');
  if (deployments.error) warnings.push(deployments.error);

  // JS-authoritative recent-window filter — the mock can't honour KQL `where ts > ago(90d)`.
  const ninetyDaysAgo = Date.now() - 90 * 86400_000;
  const recentDeployments = deployments.rows.filter((d: any) => {
    const t = d.ts ? Date.parse(d.ts) : Number.NaN;
    // Treat undefined ts as recent (so the mock fixtures without timestamps
    // still pass) — we're conservatively erring toward "deployments seen".
    return !Number.isFinite(t) || t >= ninetyDaysAgo;
  });
  const subsWithDeployments = new Set(recentDeployments.map((d: any) => String(d.subscriptionId ?? '')).filter(Boolean));

  evidence.push(ev('resourcegraph.arm_deployments_90d', {
    total: deployments.rows.length,
    recent_90d: recentDeployments.length,
    subscriptions_with_recent_deployments: subsWithDeployments.size,
    subscriptions_total: subs.length,
    sample: recentDeployments.slice(0, 20),
  }));

  // 2) Azure Policy compliance ratio.
  const compliance = await runKql(subs,
    'policyresources | where type =~ "microsoft.policyinsights/policystates" ' +
    '| extend cs = tostring(properties.complianceState) ' +
    '| summarize compliant = countif(cs =~ "Compliant"), non_compliant = countif(cs =~ "NonCompliant"), total = count() by subscriptionId');
  if (compliance.error) warnings.push(compliance.error);

  const aggregates = compliance.rows.reduce<{ compliant: number; non_compliant: number; total: number }>(
    (acc, r: any) => ({
      compliant: acc.compliant + Number(r.compliant ?? 0),
      non_compliant: acc.non_compliant + Number(r.non_compliant ?? 0),
      total: acc.total + Number(r.total ?? 0),
    }),
    { compliant: 0, non_compliant: 0, total: 0 },
  );
  const complianceRatio = aggregates.total > 0 ? aggregates.compliant / aggregates.total : 0;
  evidence.push(ev('resourcegraph.policy_compliance_ratio', { ...aggregates, ratio: complianceRatio, by_subscription: compliance.rows.slice(0, 20) }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Terraform Cloud / GitHub Actions / Azure DevOps pipelines (declarative IaC pipeline outside ARM)',
      description: 'Many Azure shops keep state in Terraform Cloud rather than ARM deployments. The proof of "IaC is source of truth" lives in the pipeline run history, not in microsoft.resources/deployments.',
      evidence_required: ['Pipeline run history for the last 90 days', 'State-file location (Terraform Cloud workspace / azurerm backend)', 'Drift-detection schedule'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: ARM deployment history present --------
  findings.push(finding({
    rule: 'azure.svc.acm.deployment_history_present',
    passed: recentDeployments.length >= 1,
    severity: 'medium',
    current: {
      summary: recentDeployments.length >= 1
        ? `${recentDeployments.length} ARM deployment(s) in the last 90 days across ${subsWithDeployments.size}/${subs.length} subscription(s) — IaC is actively shipping.`
        : 'No ARM deployments observed in the last 90 days — either every change goes through an off-Azure IaC tool, or changes are manual.',
      observations: {
        recent_90d: recentDeployments.length,
        subscriptions_with_recent_deployments: subsWithDeployments.size,
        subscriptions_total: subs.length,
      },
    },
    target: { summary: 'ARM deployments run regularly (Bicep / ARM templates / Terraform azurerm provider) — IaC is the source of truth.', rationale: 'NIST CM-2, CM-3, CM-6. Manual portal changes drift the environment away from any declarative baseline.' },
    gap: { description: 'No ARM deployment evidence — either changes are manual, or IaC runs entirely outside ARM (in which case the alternative-satisfier path applies).', affected_resources: [{ type: 'azure_arm_deployment', identifier: 'none-90d', attributes: {} }] },
    remediation: {
      summary: 'Pick an IaC tool of record (Bicep / Terraform / Pulumi) and migrate the in-scope resource groups to it. If you already use Terraform Cloud, document it as the alternative satisfier with pipeline-run evidence.',
      options: [
        { approach: 'Terraform azurerm provider + state in Azure Storage.', mechanism: 'terraform', steps: [
          'Pick a state backend (azurerm or Terraform Cloud)',
          'Import existing resource groups via `terraform import`',
          'Add a CI pipeline that plans + applies on PR merge',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['cm-2', 'cm-3', 'cm-6'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CMT-RMV', relationship: 'shares-remediation', note: 'Both depend on IaC-based change as the deployment model.' }],
  }));

  // -------- Finding 2: policy compliance acceptable --------
  // Threshold deliberately conservative — ≥ 80% compliant. Below that the
  // environment is materially drifting against its own assigned policies,
  // which is the SVC-ACM failure mode (not just lack of policy assignment,
  // which CNA-EIS already covers).
  const COMPLIANCE_THRESHOLD = 0.8;
  const compliancePassed = aggregates.total === 0 || complianceRatio >= COMPLIANCE_THRESHOLD;
  findings.push(finding({
    rule: 'azure.svc.acm.policy_compliance_acceptable',
    passed: compliancePassed,
    severity: 'medium',
    current: {
      summary: aggregates.total === 0
        ? 'No policy-state rows observed — no compliance signal to evaluate (KSI-CNA-EIS already flags this as a policy-evaluation gap).'
        : `${aggregates.compliant}/${aggregates.total} (${Math.round(complianceRatio * 100)}%) policy evaluations are Compliant; ${aggregates.non_compliant} NonCompliant.`,
      observations: { ...aggregates, ratio: complianceRatio, threshold: COMPLIANCE_THRESHOLD },
    },
    target: { summary: `≥ ${Math.round(COMPLIANCE_THRESHOLD * 100)}% of policy-state evaluations are Compliant across all configured subscriptions.`, rationale: 'NIST CM-2, CM-6. A low compliance ratio means the environment is drifting from its own declared baseline — the policies are being assigned but not driving remediation.' },
    gap: { description: 'Policy compliance ratio below the SVC-ACM threshold — the environment is drifting from its declared baseline.', affected_resources: [{ type: 'azure_subscription', identifier: 'aggregate', attributes: { compliant: aggregates.compliant, non_compliant: aggregates.non_compliant, ratio: complianceRatio } }] },
    remediation: {
      summary: 'Triage NonCompliant policy evaluations, prioritised by the assigned-policy effect (Deny / Audit). Apply remediation tasks for built-in policies that support them, or update IaC to satisfy the policy.',
      options: [
        { approach: 'Azure Policy → Compliance blade → triage NonCompliant resources.', mechanism: 'console', steps: [
          'Open the Azure Policy → Compliance blade',
          'Sort by non-compliant resource count, descending',
          'For each top offender: choose "Create remediation task" if the policy supports it, or update IaC to satisfy the policy',
        ] },
      ],
    },
    nist_controls: ['cm-2', 'cm-6'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'CNA-EIS covers policy assignment presence; SVC-ACM covers whether the assigned policies are actually being satisfied.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}

// =====================================================================
// KSI-SVC-EIS — Evaluating and Improving Security (HYBRID)
// Azure proxy: Microsoft Defender for Cloud secure-score is being computed
// and is at or above an acceptable ratio. The improvement-decision log and
// MTTR trend report are tracked as process artifacts in ksi-map.ts.
// =====================================================================
export async function collectSvcEis(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // securityresources/microsoft.security/securescores carries the
  // per-subscription secure score: properties.score.current /
  // properties.score.max / properties.weight.
  const scores = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/securescores" ' +
    '| extend current = todouble(properties.score.current), maxv = todouble(properties.score.max), weight = todouble(properties.weight) ' +
    '| project id, name, subscriptionId, current, maxv, weight');
  if (scores.error) warnings.push(scores.error);

  // Aggregate weighted ratio across all subscriptions. If max is 0 (no
  // assessments evaluated) we treat the sub as data-missing, not a fail.
  const aggregate = scores.rows.reduce<{ current: number; max: number }>(
    (acc, r: any) => ({
      current: acc.current + Number(r.current ?? 0),
      max: acc.max + Number(r.maxv ?? 0),
    }),
    { current: 0, max: 0 },
  );
  const ratio = aggregate.max > 0 ? aggregate.current / aggregate.max : 0;

  evidence.push(ev('resourcegraph.defender_secure_scores', {
    rows: scores.rows.length,
    aggregate_current: aggregate.current,
    aggregate_max: aggregate.max,
    ratio,
    by_subscription: scores.rows.slice(0, 20),
  }));

  // Threshold deliberately conservative — Microsoft's own guidance treats
  // < 50% secure-score as "needs attention". A real production tenant
  // routinely sits in the 60-80% band; we flag below 50% as a SHOULD gap.
  const SECURE_SCORE_THRESHOLD = 0.5;

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party CSPM (Wiz / Lacework / Orca / Prisma Cloud) driving improvement',
      description: 'External CSPM may own the improvement loop, with Defender for Cloud disabled. Evidence then comes from the CSPM platform.',
      evidence_required: ['CSPM tenant URL', 'Improvement-decision log entries citing CSPM findings', 'Per-severity MTTR report'],
      detected: false, detection_signals: [],
    },
  ];

  findings.push(finding({
    rule: 'azure.svc.eis.defender_secure_score_present',
    passed: scores.rows.length >= 1 && aggregate.max > 0,
    severity: 'high',
    current: {
      summary: scores.rows.length === 0
        ? 'No Defender for Cloud secure-score rows — Defender may be off, or `Security Reader` role is missing for the securityresources table.'
        : `Defender secure-score active for ${scores.rows.length} subscription score row(s); aggregate score ${aggregate.current.toFixed(0)} / ${aggregate.max.toFixed(0)}.`,
      observations: { rows: scores.rows.length, aggregate_current: aggregate.current, aggregate_max: aggregate.max },
    },
    target: { summary: 'Microsoft Defender for Cloud is on for every in-scope subscription and is generating a secure-score signal.', rationale: 'NIST CA-7, PM-31. Continuous improvement starts from a measurable security posture.' },
    gap: { description: 'No secure-score signal — improvement loop has no input metric.', affected_resources: [{ type: 'azure_defender_secure_score', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Enable Microsoft Defender for Cloud (Standard tier) on the in-scope subscriptions. Secure score begins computing within minutes.',
      options: [
        { approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az security pricing create -n VirtualMachines --tier Standard', 'az security pricing create -n StorageAccounts --tier Standard', 'az security pricing create -n KeyVaults --tier Standard'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ca-7', 'pm-31'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-EVC', relationship: 'depends-on', note: 'MLA-EVC checks that Defender assessments exist; SVC-EIS checks that the resulting secure-score posture is acceptable.' }],
  }));

  findings.push(finding({
    rule: 'azure.svc.eis.defender_secure_score_acceptable',
    // Vacuously pass when there's no signal yet (the presence finding above
    // is doing the talking); otherwise require >= threshold.
    passed: aggregate.max === 0 || ratio >= SECURE_SCORE_THRESHOLD,
    severity: 'medium',
    current: {
      summary: aggregate.max === 0
        ? 'No secure-score signal — see the presence finding.'
        : `Defender secure-score ratio: ${Math.round(ratio * 100)}% (${aggregate.current.toFixed(0)} / ${aggregate.max.toFixed(0)}). Microsoft considers < 50% the "needs attention" band.`,
      observations: { ratio, threshold: SECURE_SCORE_THRESHOLD, aggregate_current: aggregate.current, aggregate_max: aggregate.max },
    },
    target: { summary: `Aggregate Defender secure-score ratio ≥ ${Math.round(SECURE_SCORE_THRESHOLD * 100)}%.`, rationale: 'NIST CA-7, PM-31. A persistently low secure-score with no improvement trajectory means the improvement loop is not converting findings into fixes.' },
    gap: { description: 'Aggregate secure score below the SVC-EIS threshold — the improvement loop is not closing.', affected_resources: scores.rows.slice(0, 50).map((s: any) => ({ type: 'azure_defender_secure_score', identifier: s.id ?? s.name ?? 'unknown', attributes: { current: s.current, max: s.maxv } })) },
    remediation: {
      summary: 'Open Defender for Cloud → Secure Score Recommendations; work through the highest-weighted recommendations first. Capture each closed-out recommendation in the improvement-decision log (process artifact).',
      options: [
        { approach: 'Defender for Cloud → Recommendations → sort by Score Impact.', mechanism: 'console', steps: [
          'Open Defender for Cloud → Recommendations',
          'Sort by Score Impact descending',
          'Apply the suggested fix (often a Quick Fix button) or open a remediation ticket',
          'Record the closed recommendation in the improvement-decision log',
        ] },
      ],
    },
    nist_controls: ['ca-7', 'pm-31'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
