/**
 * Azure supply-chain KSI collectors.
 *
 *   - KSI-CMT-RMV — Redeploying vs Modifying. Azure-canonical signals for
 *     "immutable artifacts redeployed instead of mutated in place":
 *       1. At least one Azure Container Registry exists (something is being
 *          built into a versioned artifact at all).
 *       2. Every ACR has `adminUserEnabled = false` — the legacy shared
 *          admin user is a single static credential with full push/pull;
 *          enabling it breaks per-identity audit and the least-privilege
 *          assumption that ties RMV to RBAC.
 *
 *   - KSI-CMT-VTD — Validating Throughout Deployment (HYBRID). Azure's
 *     canonical "is automated validation wired up?" signal is Microsoft
 *     Defender for DevOps + Defender for Containers:
 *       1. At least one Defender for DevOps security connector exists
 *          (ADO / GitHub / GitLab — the source-of-truth where IaC + app
 *          code + container builds get scanned pre-deploy).
 *       2. Defender for Containers is on Standard tier (otherwise the
 *          registry / runtime image scanning isn't producing findings).
 *
 *   - KSI-SCR-MON — Monitoring Supply Chain Risk (HYBRID). Two signals:
 *       1. Microsoft Defender Vulnerability Management is producing
 *          evidence — proxied by `microsoft.security/pricings` for
 *          VirtualMachines / Servers / Containers on Standard tier.
 *       2. At least one Defender security contact is configured with an
 *          email — vulnerability advisories actually reach a human.
 *
 * RMV is on AZ-1's `Reader` only. VTD + SCR-MON need `Security Reader`
 * for the `securityresources` table (same constraint MLA-EVC + SVC-EIS
 * document).
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
// KSI-CMT-RMV — Redeploying vs Modifying
// =====================================================================
export async function collectCmtRmv(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const registries = await runKql(subs,
    'Resources | where type =~ "microsoft.containerregistry/registries" ' +
    '| extend admin = tobool(properties.adminUserEnabled), ' +
    'anonPull = tobool(properties.anonymousPullEnabled), ' +
    'softDelete = tostring(properties.policies.softDeletePolicy.status), ' +
    'trust = tostring(properties.policies.trustPolicy.status) ' +
    '| project id, name, subscriptionId, location, admin, anonPull, softDelete, trust');
  if (registries.error) warnings.push(registries.error);

  const total = registries.rows.length;
  // adminUserEnabled = true is the failure case. Treat undefined/null as
  // "not explicitly enabled" — the ACR default is false.
  const adminOn = registries.rows.filter((r: any) => r.admin === true);
  const anonOn = registries.rows.filter((r: any) => r.anonPull === true);
  const softDeleteOn = registries.rows.filter((r: any) => String(r.softDelete ?? '').toLowerCase() === 'enabled').length;
  const trustOn = registries.rows.filter((r: any) => String(r.trust ?? '').toLowerCase() === 'enabled').length;

  evidence.push(ev('resourcegraph.container_registries', {
    total, admin_user_enabled: adminOn.length, anonymous_pull_enabled: anonOn.length,
    soft_delete_enabled: softDeleteOn, content_trust_enabled: trustOn,
    sample: registries.rows.slice(0, 20),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Off-Azure registry (ECR / GCR / GHCR / Docker Hub) with signing + immutability enforced upstream',
      description: 'Many teams keep images in a different registry; the immutability + signing story moves with the registry.',
      evidence_required: ['Registry inventory + signing config', 'Sample signature verification output', 'Tag immutability policy'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: ACR present --------
  findings.push(finding({
    rule: 'azure.cmt.rmv.acr_present', passed: total >= 1, severity: 'medium',
    current: {
      summary: total >= 1
        ? `${total} Azure Container Registry(ies) inventoried — images are versioned artifacts.`
        : 'No Azure Container Registries observed — either container images live in an off-Azure registry (alt satisfier) or the workload isn\'t containerized.',
      observations: { total },
    },
    target: { summary: 'At least one ACR exists, OR a documented off-Azure registry with equivalent signing + immutability controls.', rationale: 'NIST CM-2, CM-3, SA-10. A versioned image registry is the precondition for redeploy-not-modify workflows.' },
    gap: { description: 'No ACR — verify the container image story lives elsewhere (alternative satisfier).', affected_resources: [{ type: 'azure_container_registry', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Provision an ACR per environment, or document the off-Azure registry as the alternative satisfier.',
      options: [
        { approach: 'Terraform azurerm_container_registry.', mechanism: 'terraform', steps: [
          'Declare azurerm_container_registry with sku = "Premium" (Premium adds geo-replication + content trust)',
          'Set admin_enabled = false; use RBAC (AcrPush / AcrPull roles)',
          'Wire CI pipelines to push tagged images',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['cm-2', 'cm-3', 'sa-10'],
  }));

  // -------- Finding 2: admin user disabled on every ACR --------
  const adminPassed = total === 0 || adminOn.length === 0;
  findings.push(finding({
    rule: 'azure.cmt.rmv.acr_admin_user_disabled', passed: adminPassed, severity: 'high',
    current: {
      summary: total === 0
        ? 'No ACRs to evaluate.'
        : adminOn.length === 0
          ? `Every ACR (${total}) has the legacy admin user disabled — RBAC is the only path to push/pull.`
          : `${adminOn.length}/${total} ACR(s) have the legacy admin user enabled — anyone with the shared admin credential bypasses RBAC and per-identity audit.`,
      observations: { total, admin_user_enabled: adminOn.length, sample_offenders: adminOn.slice(0, 10).map((r: any) => r.name) },
    },
    target: { summary: 'Every ACR has `adminUserEnabled = false`; image push/pull goes through RBAC (AcrPush / AcrPull) tied to Entra identities.', rationale: 'NIST AC-2, AC-3, AC-6. The ACR admin user is a single shared static credential — no per-identity attribution.' },
    gap: { description: 'Legacy admin user means anyone with the password is indistinguishable in the audit log.', affected_resources: adminOn.slice(0, 50).map((r: any) => ({ type: 'azure_container_registry', identifier: r.id, attributes: { name: r.name, admin_user_enabled: true } })) },
    remediation: {
      summary: 'Disable the admin user on every ACR and migrate consumers to RBAC.',
      options: [
        { approach: 'az CLI per registry.', mechanism: 'cli', steps: ['az acr update -n <acr> --admin-enabled false', 'Bind AcrPull to consumer identities (AKS / Container Apps / Functions managed identity)', 'Bind AcrPush to CI service principals only'] },
        { approach: 'Terraform azurerm_container_registry.admin_enabled = false.', mechanism: 'terraform', steps: ['Set admin_enabled = false on every azurerm_container_registry', 'Replace any acr-credential pulls with managed-identity AcrPull bindings'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ac-2', 'ac-3', 'ac-6'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'RBAC-only push/pull is the IAM-ELP story applied to the registry.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}

// =====================================================================
// KSI-CMT-VTD — Validating Throughout Deployment (HYBRID)
// =====================================================================
export async function collectCmtVtd(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Defender for DevOps security connectors — the modern "scan IaC + app
  // code + container builds at the source of truth" surface. Looks at
  // microsoft.security/securityconnectors filtered to ADO / GitHub / GitLab.
  const devopsConnectors = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/securityconnectors" ' +
    '| extend env = tostring(properties.environmentName) ' +
    '| where env in~ ("AzureDevOps", "GitHub", "GitLab") ' +
    '| project id, name, subscriptionId, env');
  if (devopsConnectors.error) warnings.push(devopsConnectors.error);

  // JS-side defensive filter — the test mock only routes on substring, so
  // re-apply the in-set predicate here.
  const ALLOWED_ENVS = new Set(['azuredevops', 'github', 'gitlab']);
  const validConnectors = devopsConnectors.rows.filter((c: any) => {
    const e = String(c.env ?? '').toLowerCase();
    // When the mock omits `env`, accept the row (covers fixtures that
    // pre-filter at the route level).
    return e === '' || ALLOWED_ENVS.has(e);
  });

  // Defender for Containers pricing plan — on/off per subscription.
  const containerPricing = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/pricings" ' +
    '| extend planName = tostring(name), tier = tostring(properties.pricingTier) ' +
    '| where planName in~ ("Containers", "ContainerRegistry") ' +
    '| project id, name, subscriptionId, planName, tier');
  if (containerPricing.error) warnings.push(containerPricing.error);

  const containerStandardSubs = new Set(containerPricing.rows
    .filter((p: any) => String(p.tier ?? '').toLowerCase() === 'standard')
    .map((p: any) => String(p.subscriptionId ?? '')));
  const containerSubsWithRow = new Set(containerPricing.rows.map((p: any) => String(p.subscriptionId ?? '')));

  evidence.push(ev('resourcegraph.defender_for_devops_connectors', {
    total: validConnectors.length,
    by_env: validConnectors.reduce<Record<string, number>>((acc, c: any) => {
      const e = String(c.env ?? 'unknown'); acc[e] = (acc[e] ?? 0) + 1; return acc;
    }, {}),
    sample: validConnectors.slice(0, 10),
  }));
  evidence.push(ev('resourcegraph.defender_for_containers_pricing', {
    rows: containerPricing.rows.length,
    standard_subscriptions: containerStandardSubs.size,
    subscriptions_with_pricing_row: containerSubsWithRow.size,
    sample: containerPricing.rows.slice(0, 10),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'GitHub Advanced Security / GitLab Ultimate scanning (without Defender for DevOps)',
      description: 'SAST + SCA + secret scanning lives entirely in the platform tier of the source-of-truth repo, with results captured outside Defender.',
      evidence_required: ['CodeQL / SAST configuration', 'Recent scan run log', 'Severity-SLA matrix'],
      detected: false, detection_signals: [],
    },
    {
      via: '3rd-party CI gates (Snyk / Aqua / Trivy / Checkov / Anchore)',
      description: '3rd-party scanners run in the CI pipeline before deploy.',
      evidence_required: ['Scanner config in CI workflow', 'Sample blocking finding', 'Gate-effectiveness review'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: Defender for DevOps connector present --------
  findings.push(finding({
    rule: 'azure.cmt.vtd.defender_devops_connector_present',
    passed: validConnectors.length >= 1,
    severity: 'medium',
    current: {
      summary: validConnectors.length >= 1
        ? `${validConnectors.length} Defender for DevOps connector(s) — IaC + app code + container builds scanned pre-deploy.`
        : 'No Defender for DevOps connectors — if validation runs in GitHub Advanced Security / a 3rd-party CI gate instead, document via the alternative satisfier.',
      observations: { total: validConnectors.length },
    },
    target: { summary: 'At least one Defender for DevOps security connector exists (ADO / GitHub / GitLab) OR an equivalent CI-gate is documented.', rationale: 'NIST CM-3(2), SA-11. Persistent validation has to run at the source-of-truth before deploy lands.' },
    gap: { description: 'No automated pre-deploy validation surface visible in Azure — relies on undocumented operator discipline.', affected_resources: [{ type: 'azure_defender_devops_connector', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Onboard the source-of-truth repos (ADO / GitHub / GitLab) into Defender for DevOps via the portal connector flow.',
      options: [
        { approach: 'Defender for Cloud → Environment settings → Add environment → DevOps.', mechanism: 'console', steps: [
          'Defender for Cloud → Environment settings',
          'Add environment → choose Azure DevOps / GitHub / GitLab',
          'Sign in to the source-of-truth account; pick orgs/projects/repos',
          'Wait for the first scan to complete; verify findings in Recommendations',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['cm-3.2', 'sa-11', 'sa-11.1'],
  }));

  // -------- Finding 2: Defender for Containers Standard tier --------
  const containerPassed = subs.length === 0 || containerStandardSubs.size >= 1;
  findings.push(finding({
    rule: 'azure.cmt.vtd.defender_for_containers_enabled',
    passed: containerPassed,
    severity: 'high',
    current: {
      summary: containerStandardSubs.size >= 1
        ? `Defender for Containers on Standard tier across ${containerStandardSubs.size} subscription(s) — registry + runtime image scanning is producing findings.`
        : (containerSubsWithRow.size > 0
          ? `${containerSubsWithRow.size} subscription(s) report a Defender pricing row but none are on Standard for Containers — scanning isn't active.`
          : 'No Defender for Containers pricing row visible — either the plan is off or Security Reader access is missing.'),
      observations: {
        standard_subscriptions: containerStandardSubs.size,
        subscriptions_with_pricing_row: containerSubsWithRow.size,
        subscriptions_total: subs.length,
      },
    },
    target: { summary: 'Defender for Containers is on Standard tier for every in-scope subscription.', rationale: 'NIST SA-11, SI-7. Without the Standard tier the registry + runtime image scans don\'t run.' },
    gap: { description: 'Container image scanning isn\'t producing findings — the validation chain is silently broken.', affected_resources: [{ type: 'azure_defender_pricing', identifier: 'aggregate', attributes: { standard_subscriptions: containerStandardSubs.size, total_subscriptions: subs.length } }] },
    remediation: {
      summary: 'Turn on Defender for Containers (Standard tier) on every in-scope subscription.',
      options: [
        { approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az security pricing create -n Containers --tier Standard --subscription <id>', 'Repeat per subscription'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sa-11', 'si-7'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-MLA-EVC', relationship: 'shares-remediation', note: 'Both depend on Defender for Cloud being enabled.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}

// =====================================================================
// KSI-SCR-MON — Monitoring Supply Chain Risk (HYBRID)
// =====================================================================
// Plan names from Defender for Cloud that deliver upstream-vulnerability
// telemetry (Microsoft Defender Vulnerability Management bundles into these
// plans). Any one of them on Standard tier proves MDVM is producing evidence.
const MDVM_PLANS = new Set(['virtualmachines', 'servers', 'containers', 'containerregistry']);

export async function collectScrMon(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Defender plans gating MDVM. We reuse the same pricings table CMT-VTD
  // queries but filter to the MDVM-bearing plans.
  const pricings = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/pricings" ' +
    '| extend planName = tostring(name), tier = tostring(properties.pricingTier) ' +
    '| project id, name, subscriptionId, planName, tier');
  if (pricings.error) warnings.push(pricings.error);
  const mdvmStandard = pricings.rows.filter((p: any) => {
    const plan = String(p.planName ?? '').toLowerCase();
    return MDVM_PLANS.has(plan) && String(p.tier ?? '').toLowerCase() === 'standard';
  });

  // 2) Security contacts — proves vulnerability advisories actually reach a human.
  // microsoft.security/securityContacts carries properties.emails (comma-joined)
  // and properties.alertNotifications.state = "On" / "Off".
  const contacts = await runKql(subs,
    'securityresources | where type =~ "microsoft.security/securitycontacts" ' +
    '| extend emails = tostring(properties.emails), ' +
    'alertState = tostring(properties.alertNotifications.state) ' +
    '| project id, name, subscriptionId, emails, alertState');
  if (contacts.error) warnings.push(contacts.error);
  const goodContacts = contacts.rows.filter((c: any) => {
    const email = String(c.emails ?? '').trim();
    const alert = String(c.alertState ?? '').toLowerCase();
    return email.length > 0 && (alert === '' || alert === 'on');
  });

  evidence.push(ev('resourcegraph.defender_mdvm_pricings', {
    rows: pricings.rows.length,
    standard_plan_subscriptions: new Set(mdvmStandard.map((p: any) => String(p.subscriptionId ?? ''))).size,
    standard_plans: mdvmStandard.map((p: any) => ({ sub: p.subscriptionId, plan: p.planName })),
    sample: pricings.rows.slice(0, 10),
  }));
  evidence.push(ev('resourcegraph.defender_security_contacts', {
    total: contacts.rows.length,
    with_email_and_alerts: goodContacts.length,
    sample: contacts.rows.slice(0, 10),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party vulnerability-feed subscription (Snyk Advisor / GitHub Dependabot / Mend Renovate)',
      description: 'Upstream-CVE monitoring runs entirely outside Defender; advisories land in the SCM platform with auto-PR remediation.',
      evidence_required: ['Tool tenant URL', 'Sample advisory + auto-PR', 'Severity-SLA matrix'],
      detected: false, detection_signals: [],
    },
    {
      via: 'Vendor advisory mailing lists (CISA, MSRC, NVD RSS) routed to security@',
      description: 'Operator subscribes to authoritative upstream advisory channels manually.',
      evidence_required: ['Subscription list', 'Last-30-days advisory triage log'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: MDVM-bearing plan on Standard --------
  findings.push(finding({
    rule: 'azure.scr.mon.defender_mdvm_active', passed: mdvmStandard.length >= 1, severity: 'high',
    current: {
      summary: mdvmStandard.length >= 1
        ? `Defender Vulnerability Management is active via ${mdvmStandard.length} Standard-tier plan(s) (${mdvmStandard.map((p: any) => p.planName).join(', ')}).`
        : (pricings.rows.length > 0
          ? `${pricings.rows.length} Defender pricing row(s) but none of VirtualMachines / Servers / Containers / ContainerRegistry is on Standard — MDVM feed isn't running.`
          : 'No Defender pricing rows visible — either Defender is off or Security Reader is missing.'),
      observations: {
        mdvm_standard_plans: mdvmStandard.length,
        total_pricing_rows: pricings.rows.length,
      },
    },
    target: { summary: 'At least one of VirtualMachines / Servers / Containers / ContainerRegistry Defender plans is on Standard tier, OR a 3rd-party vuln-feed is documented as alt satisfier.', rationale: 'NIST SR-3, RA-5. Upstream-vulnerability monitoring needs a feed.' },
    gap: { description: 'No upstream-vulnerability telemetry from Defender — relies on the alt-satisfier path or undocumented manual review.', affected_resources: [{ type: 'azure_defender_pricing', identifier: 'mdvm-aggregate', attributes: { standard_count: mdvmStandard.length } }] },
    remediation: {
      summary: 'Turn on Defender for Servers (or Containers / VirtualMachines) on Standard tier in at least one in-scope subscription, OR document the 3rd-party feed.',
      options: [
        { approach: 'az CLI per subscription.', mechanism: 'cli', steps: ['az security pricing create -n VirtualMachines --tier Standard --subscription <id>', 'az security pricing create -n Containers --tier Standard --subscription <id>'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sr-3', 'ra-5'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-CMT-VTD', relationship: 'shares-remediation', note: 'CMT-VTD checks Containers plan; SCR-MON broadens to the Servers / VMs surface for upstream CVE feeds.' }],
  }));

  // -------- Finding 2: security contact with email + alerts on --------
  findings.push(finding({
    rule: 'azure.scr.mon.security_contact_configured', passed: goodContacts.length >= 1, severity: 'medium',
    current: {
      summary: goodContacts.length >= 1
        ? `${goodContacts.length} Defender security contact(s) with email + alert notifications enabled — advisories reach a human.`
        : (contacts.rows.length > 0
          ? `${contacts.rows.length} security contact(s) exist but none have an email + alert-state of On — Defender advisories drop on the floor.`
          : 'No Defender security contacts configured — vulnerability advisories have no destination.'),
      observations: {
        total_contacts: contacts.rows.length, contacts_with_email_and_alerts: goodContacts.length,
      },
    },
    target: { summary: 'At least one Defender security contact has a non-empty `emails` field AND `alertNotifications.state = "On"`.', rationale: 'NIST IR-6, SR-3. Vulnerability advisories that nobody reads are no advisories at all.' },
    gap: { description: 'Defender advisories have no destination — the upstream CVE feed exists but signals never reach an operator.', affected_resources: [{ type: 'azure_defender_security_contact', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Set the Defender security contact in the portal: Defender for Cloud → Environment settings → subscription → Email notifications.',
      options: [
        { approach: 'Defender for Cloud → Email notifications.', mechanism: 'console', steps: [
          'Defender for Cloud → Environment settings',
          'Pick subscription → Email notifications',
          'Set the on-call distribution list as the recipient; toggle High-severity + Attack-path alerts on',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ir-6', 'sr-3'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
