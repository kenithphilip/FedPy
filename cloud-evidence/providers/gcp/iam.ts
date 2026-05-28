/**
 * GCP IAM evidence collectors.
 *
 * One exported function per IAM KSI, mirroring providers/aws/iam.ts.
 * All calls are read-only (.get / .list / .search / .recommend* / .export*).
 *
 * Some Workspace / Cloud Identity APIs require admin scopes that the
 * runner's ADC may not have. Those collectors degrade gracefully with a
 * warning rather than failing the whole run.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function nowIso(): string {
  return new Date().toISOString();
}
function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: nowIso(), data: data === undefined ? null : data };
}

interface Ctx {
  project: string;
}

function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

// =====================================================================
// KSI-IAM-AAM — Automating Account Management
// =====================================================================
export async function collectIamAam(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---- Service accounts in the project ----
  let saCount = 0;
  let saWithUserKeys: Array<{ sa: string; keys: number }> = [];
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    const sas = await iam.projects.serviceAccounts.list({ name: `projects/${ctx.project}`, pageSize: 100 });
    const accounts = sas.data.accounts ?? [];
    saCount = accounts.length;
    for (const sa of accounts) {
      try {
        const kr = await iam.projects.serviceAccounts.keys.list({
          name: sa.name,
          keyTypes: ['USER_MANAGED'],
        });
        const keys = kr.data.keys?.length ?? 0;
        if (keys > 0) saWithUserKeys.push({ sa: sa.email ?? sa.name ?? '?', keys });
      } catch (e) {
        warnings.push(diagnoseGcpError(e, `iam.projects.serviceAccounts.keys.list (${sa.email})`, 'iam.serviceAccountKeys.list (roles/iam.serviceAccountViewer)'));
      }
    }
    evidence.push(ev('iam.projects.serviceAccounts.list', { count: saCount, sas_with_user_managed_keys: saWithUserKeys }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'iam.projects.serviceAccounts.list', 'iam.serviceAccounts.list (roles/iam.serviceAccountViewer)'));
  }

  // ---- Org policy: iam.disableServiceAccountKeyCreation ----
  let saKeyCreationDisabled = false;
  try {
    const orgpolicy = await gcpAuth.googleClient<any>('orgpolicy', 'v2');
    // Try project-level constraint
    try {
      const got = await orgpolicy.projects.policies.get({
        name: `projects/${ctx.project}/policies/iam.disableServiceAccountKeyCreation`,
      });
      const enforce = got.data.spec?.rules?.[0]?.enforce ?? got.data.spec?.rules?.[0]?.allowAll === false;
      if (enforce === true) saKeyCreationDisabled = true;
      evidence.push(ev('orgpolicy.iam.disableServiceAccountKeyCreation', got.data));
    } catch (e) {
      // Not set at project level; could be inherited. Mark warning, not failure.
      warnings.push(diagnoseGcpError(e, 'orgpolicy.projects.policies.get (iam.disableServiceAccountKeyCreation)', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)'));
    }
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'orgpolicy.googleClient', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)'));
  }

  // ---- IAM Recommender: idle service accounts ----
  let idleSaFindings = 0;
  try {
    const recommender = await gcpAuth.googleClient<any>('recommender', 'v1');
    const parent = `projects/${ctx.project}/locations/global/recommenders/google.iam.serviceAccount.IdleRecommender`;
    const r = await recommender.projects.locations.recommenders.recommendations.list({ parent, pageSize: 100 });
    idleSaFindings = r.data.recommendations?.length ?? 0;
    evidence.push(ev('recommender.iam.serviceAccount.IdleRecommender', { count: idleSaFindings }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'recommender.iam.serviceAccount.IdleRecommender.list', 'recommender.*.list (roles/recommender.viewer)'));
  }

  // ---- IAM Recommender: over-privilege ----
  let overPrivilegeFindings = 0;
  try {
    const recommender = await gcpAuth.googleClient<any>('recommender', 'v1');
    const parent = `projects/${ctx.project}/locations/global/recommenders/google.iam.policy.Recommender`;
    const r = await recommender.projects.locations.recommenders.recommendations.list({ parent, pageSize: 100 });
    overPrivilegeFindings = r.data.recommendations?.length ?? 0;
    evidence.push(ev('recommender.iam.policy.Recommender', { count: overPrivilegeFindings }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'recommender.iam.policy.Recommender.list', 'recommender.*.list (roles/recommender.viewer)'));
  }

  // ---- Workforce Identity Federation pools (need iam v1.locations.workforcePools) ----
  let workforcePoolCount = 0;
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    // workforcePools live at organizations/{id}/locations/global; require org-level scope.
    // If we don't have org-level access, this throws.
    const orgId = process.env.GCP_ORGANIZATION_ID;
    if (orgId) {
      const r = await iam.locations.workforcePools.list({ parent: `locations/global`, pageSize: 50 });
      workforcePoolCount = r.data.workforcePools?.length ?? 0;
      evidence.push(ev('iam.locations.workforcePools.list', { count: workforcePoolCount }));
    } else {
      warnings.push('Workforce Identity Federation: skipped (GCP_ORGANIZATION_ID not set)');
    }
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'iam.locations.workforcePools.list', 'iam.workforcePools.list (roles/iam.workforcePoolViewer)'));
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External IdP with SCIM/group sync (Okta, Azure AD, Google Workspace)',
      description: 'SCIM provisioning of Cloud Identity groups pushes lifecycle to the IdP.',
      evidence_required: ['IdP SCIM provisioning config export', 'Sample provisioning event log'],
      detected: workforcePoolCount > 0,
      detection_signals: [`Workforce Identity Federation pools: ${workforcePoolCount}`],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.sa.no_user_managed_keys',
      passed: saWithUserKeys.length === 0,
      severity: 'critical',
      current: {
        summary: saWithUserKeys.length === 0
          ? 'No service accounts have user-managed (downloadable) keys.'
          : `${saWithUserKeys.length} service account(s) have user-managed keys, which are an anti-pattern.`,
        observations: { sa_total: saCount, sa_with_user_managed_keys: saWithUserKeys },
      },
      target: {
        summary: 'Zero user-managed SA keys. All SAs authenticate via short-lived tokens (Workload Identity Federation, GKE Workload Identity, or Compute Engine identity).',
        rationale: 'Long-lived SA JSON keys are the most common source of GCP credential leaks. NIST IA-5(1) and FedRAMP 20x IAM-SNU explicitly call for short-lived credentials.',
      },
      gap: saWithUserKeys.length === 0 ? undefined : {
        description: 'Each user-managed SA key is a long-lived secret in some downstream consumer; if leaked it grants the SA\'s privileges.',
        affected_resources: saWithUserKeys.map<AffectedResource>((s) => ({
          type: 'google_service_account_key', identifier: s.sa, name: s.sa, attributes: { user_managed_key_count: s.keys },
        })),
      },
      remediation: saWithUserKeys.length === 0 ? undefined : {
        summary: 'Replace each SA key with Workload Identity Federation (off-GCP) or Workload Identity (on-GKE).',
        options: [{
          approach: 'Migrate off-GCP workloads (CI/CD, on-prem) to Workload Identity Federation.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'WIF is free.' },
          availability_impact: { level: 'medium', notes: 'Workload reconfiguration; per-workload validation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per workload.' },
          steps: [
            'Create a workload identity pool + provider for the external IdP (GitHub OIDC, AWS, Azure AD, etc.).',
            'Grant the pool\'s principal access to the target SA via roles/iam.workloadIdentityUser.',
            'Update workload to exchange external token for SA token.',
            'Delete the user-managed SA key.',
          ],
          example_code: `resource "google_iam_workload_identity_pool" "ci" {
  workload_identity_pool_id = "github-ci"
}
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.ci.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
  attribute_mapping = { "google.subject" = "assertion.sub", "attribute.repository" = "assertion.repository" }
}
resource "google_service_account_iam_binding" "wif" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  members            = ["principalSet://iam.googleapis.com/projects/$\${PROJECT_NUM}/locations/global/workloadIdentityPools/github-ci/attribute.repository/your-org/your-repo"]
}`,
          references: [{ title: 'GCP docs: Workload Identity Federation', url: 'https://cloud.google.com/iam/docs/workload-identity-federation' }],
        }, {
          approach: 'For GKE workloads, configure Workload Identity (per-namespace).',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Cluster-level config; per-namespace migration.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Cluster setup + per-namespace.' },
          steps: [
            'Enable Workload Identity on the GKE cluster.',
            'Annotate the Kubernetes service account with the GCP SA email.',
            'Bind the K8s SA to the GCP SA via roles/iam.workloadIdentityUser.',
            'Update workload manifests to use the K8s SA.',
            'Delete user-managed SA keys.',
          ],
          references: [{ title: 'GCP docs: GKE Workload Identity', url: 'https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-5','ia-5.1','ia-9'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Same change addresses both.' },
        { ksi_id: 'KSI-SVC-ASM', relationship: 'shares-remediation', note: 'Removes long-lived credentials from secret stores.' },
      ],
    }),

    finding({
      rule: 'gcp.org.disable_sa_key_creation_enforced',
      passed: saKeyCreationDisabled,
      severity: 'high',
      current: {
        summary: saKeyCreationDisabled
          ? 'iam.disableServiceAccountKeyCreation is enforced — no new user-managed SA keys can be created.'
          : 'iam.disableServiceAccountKeyCreation is NOT enforced — anyone with SA admin can mint new SA keys.',
        observations: { saKeyCreationDisabled },
      },
      target: {
        summary: 'iam.disableServiceAccountKeyCreation constraint is enforced at the org (or this project).',
        rationale: 'Defense in depth: even if you remediate existing keys (previous finding), a missing org-policy lets someone re-introduce the anti-pattern.',
      },
      gap: saKeyCreationDisabled ? undefined : {
        description: 'New user-managed SA keys can be created without governance.',
        affected_resources: [{ type: 'google_org_policy_policy', identifier: `projects/${ctx.project}/policies/iam.disableServiceAccountKeyCreation`, attributes: {} }],
      },
      remediation: saKeyCreationDisabled ? undefined : {
        summary: 'Enforce iam.disableServiceAccountKeyCreation at the org (preferred) or project level.',
        options: [{
          approach: 'Apply at org level via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Pre-existing keys keep working; only new key creation is blocked.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: [
            'Run inventory of current user-managed keys (previous finding).',
            'Add an explicit exception list for any SAs that cannot migrate (use orgpolicy boolean_policy.dry_run + monitor).',
            'Enforce the constraint at the org.',
          ],
          example_code: `resource "google_org_policy_policy" "disable_sa_key_creation" {
  name   = "organizations/$\${var.org_id}/policies/iam.disableServiceAccountKeyCreation"
  parent = "organizations/$\${var.org_id}"
  spec { rules { enforce = "TRUE" } }
}`,
          references: [{ title: 'GCP docs: Disable SA key creation', url: 'https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#disable_service_account_key_creation' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-2.1','ia-5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-DFP', relationship: 'shares-remediation', note: 'Same guardrail family as DFP.' },
      ],
    }),

    finding({
      rule: 'gcp.recommender.idle_sa_findings_managed',
      passed: idleSaFindings <= 10,
      severity: 'medium',
      current: {
        summary: `${idleSaFindings} idle service account recommendation(s) from IAM Recommender.`,
        observations: { idleSaFindings },
      },
      target: { summary: 'Idle SA recommendations <= 10 and trending down.', rationale: 'Idle SAs are credential surface that should be retired.' },
      gap: idleSaFindings <= 10 ? undefined : {
        description: 'Idle SAs accumulate over time; each is a potential credential to compromise.',
        affected_resources: [{ type: 'google_recommender_recommendation', identifier: 'IdleRecommender', attributes: { count: idleSaFindings } }],
      },
      remediation: idleSaFindings <= 10 ? undefined : {
        summary: 'Triage Recommender findings; delete idle SAs or document exceptions.',
        options: [{
          approach: 'Review each recommendation; delete or justify.',
          mechanism: 'process',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Deleting an in-use SA breaks workloads; verify with the linked-resources view first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-finding triage.' },
          steps: [
            'Open the IAM > Recommender > Idle service accounts view.',
            'For each finding, decide delete vs. document.',
            'Apply the recommendation or mark dismissed with reason.',
          ],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-2','ac-2.3'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Same review cadence as ELP.' },
      ],
    }),

    finding({
      rule: 'gcp.recommender.policy_recommendations_managed',
      passed: overPrivilegeFindings <= 25,
      severity: 'medium',
      current: {
        summary: `${overPrivilegeFindings} over-privilege policy recommendation(s).`,
        observations: { overPrivilegeFindings },
      },
      target: { summary: 'Policy recommendations <= 25 and trending down.', rationale: 'NIST AC-6: least privilege. Recommender highlights over-grants.' },
      gap: overPrivilegeFindings <= 25 ? undefined : {
        description: 'Over-granted IAM bindings violate least privilege.',
        affected_resources: [{ type: 'google_recommender_recommendation', identifier: 'PolicyRecommender', attributes: { count: overPrivilegeFindings } }],
      },
      remediation: overPrivilegeFindings <= 25 ? undefined : {
        summary: 'Apply Recommender suggestions (REMOVE_ROLE / REPLACE_ROLE) in IaC.',
        options: [{
          approach: 'Bulk-apply Recommender suggestions via IaC.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Removing roles can break consumers; pilot one before bulk.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Triage + IaC update + canary + rollout.' },
          steps: [
            'Export recommendations via Recommender API.',
            'For each, decide apply / dismiss / defer.',
            'Update Terraform bindings.',
            'Apply; monitor for permission errors via Cloud Logging.',
          ],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','ac-6.5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Direct ELP input.' },
      ],
    }),

    finding({
      rule: 'gcp.workforce_identity_federation.pool_present',
      passed: workforcePoolCount > 0,
      severity: 'medium',
      current: {
        summary: workforcePoolCount > 0
          ? `${workforcePoolCount} Workforce Identity Federation pool(s) configured — external workforce federated.`
          : 'No Workforce Identity Federation pools detected (may require org-level scope).',
        observations: { workforcePoolCount },
      },
      target: { summary: 'For an org with an external IdP, ≥1 WIF pool is configured so users authenticate without GCP-native passwords.', rationale: 'Federation eliminates GCP-side password management.' },
      gap: workforcePoolCount > 0 ? undefined : {
        description: 'Without WIF, external workforce users either don\'t use GCP, or use GCP via Cloud Identity passwords (separate IdP risk).',
        affected_resources: [{ type: 'google_iam_workforce_pool', identifier: 'none', attributes: {} }],
      },
      remediation: workforcePoolCount > 0 ? undefined : {
        summary: 'Set up Workforce Identity Federation with your IdP.',
        options: [{
          approach: 'Configure WIF pool + provider for your IdP.',
          mechanism: 'terraform',
          owner_team: 'Identity / IT',
          cost_impact: { level: 'none', notes: 'WIF is free.' },
          availability_impact: { level: 'low', notes: 'Net-new; existing access paths continue.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Setup is a few hours; group mapping + testing takes longer.' },
          steps: [
            'In your IdP, create a SAML or OIDC app for GCP.',
            'In GCP, create a workforce pool + provider referencing the IdP metadata.',
            'Map attributes (e.g. department) for use in IAM conditions.',
            'Grant pool principals access to projects via IAM bindings.',
          ],
          references: [{ title: 'GCP docs: Workforce Identity Federation', url: 'https://cloud.google.com/iam/docs/workforce-identity-federation' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-2','ia-12'],
    }),
  ];

  // ---- 3rd-party tool detection ----
  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    workforce_pool_count: workforcePoolCount,
    service_account_emails: [], // pulled from saWithUserKeys above if needed
  });

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-APM — Passwordless / strong auth
// =====================================================================
export async function collectIamApm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Org policy: iam.allowedPolicyMemberDomains — restricts to managed domains
  let allowedDomainsEnforced = false;
  try {
    const orgpolicy = await gcpAuth.googleClient<any>('orgpolicy', 'v2');
    try {
      const got = await orgpolicy.projects.policies.get({
        name: `projects/${ctx.project}/policies/iam.allowedPolicyMemberDomains`,
      });
      allowedDomainsEnforced = (got.data.spec?.rules ?? []).some((r: any) => r.values?.allowedValues?.length > 0);
      evidence.push(ev('orgpolicy.iam.allowedPolicyMemberDomains', got.data));
    } catch {
      warnings.push('iam.allowedPolicyMemberDomains not set at project level (may be inherited from org)');
    }
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'orgpolicy.projects.policies.get (iam.allowedPolicyMemberDomains)', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)'));
  }

  // Identity Platform tenants — if used for app users
  let identityPlatformTenants: any[] = [];
  try {
    const itp = await gcpAuth.googleClient<any>('identitytoolkit', 'v2');
    const r = await itp.projects.tenants.list({ parent: `projects/${ctx.project}`, pageSize: 50 });
    identityPlatformTenants = r.data.tenants ?? [];
    evidence.push(ev('identitytoolkit.tenants.list', identityPlatformTenants.map((t: any) => ({ name: t.name, mfaConfig: t.mfaConfig }))));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'identitytoolkit.projects.tenants.list', 'identitytoolkit.tenants.list (roles/identitytoolkit.viewer or roles/firebaseauth.viewer)'));
  }

  const tenantsWithoutMfa = identityPlatformTenants.filter((t: any) => t.mfaConfig?.state !== 'ENFORCED');

  const findings = [
    finding({
      rule: 'gcp.org.allowed_policy_member_domains_enforced',
      passed: allowedDomainsEnforced,
      severity: 'high',
      current: {
        summary: allowedDomainsEnforced
          ? 'iam.allowedPolicyMemberDomains is enforced — only members of approved domains can be granted IAM.'
          : 'iam.allowedPolicyMemberDomains is NOT enforced — external email addresses (e.g. @gmail.com) could be granted IAM.',
        observations: { allowedDomainsEnforced },
      },
      target: { summary: 'Constraint enforced at the org or this project with at least one allowed customer ID.', rationale: 'Ensures all IAM principals are governed by the org\'s IdP MFA + password policy.' },
      gap: allowedDomainsEnforced ? undefined : {
        description: 'Without this constraint, an admin could grant access to an external identity, bypassing the org IdP\'s MFA policy.',
        affected_resources: [{ type: 'google_org_policy_policy', identifier: `projects/${ctx.project}/policies/iam.allowedPolicyMemberDomains`, attributes: {} }],
      },
      remediation: allowedDomainsEnforced ? undefined : {
        summary: 'Enforce iam.allowedPolicyMemberDomains at the org (preferred) with your managed customer ID(s).',
        options: [{
          approach: 'Apply at org level via Terraform — see KSI-IAM-MFA Finding 1 for the full snippet (same constraint).',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Audit existing external-domain bindings first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Stage in test folder; gradual rollout.' },
          steps: ['Identify Cloud Identity customer IDs.', 'Apply constraint at org.', 'Test in non-prod folder.', 'Roll forward.'],
          references: [{ title: 'GCP docs: Restrict identities by domain', url: 'https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-2','ia-2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Same constraint covers MFA and APM concerns.' },
      ],
    }),

    finding({
      rule: 'gcp.identity_platform.app_user_strong_auth',
      passed: identityPlatformTenants.length === 0 || tenantsWithoutMfa.length === 0,
      severity: 'high',
      current: {
        summary: identityPlatformTenants.length === 0
          ? 'Identity Platform not in use (no tenants).'
          : (tenantsWithoutMfa.length === 0
            ? 'All Identity Platform tenants enforce MFA.'
            : `${tenantsWithoutMfa.length} of ${identityPlatformTenants.length} Identity Platform tenants do NOT enforce MFA.`),
        observations: identityPlatformTenants.map((t: any) => ({ name: t.name, mfaConfig: t.mfaConfig })),
      },
      target: { summary: 'Every Identity Platform tenant authenticating federal end-users has MFA enforced.', rationale: 'NIST IA-2(1) for application end-users.' },
      gap: (identityPlatformTenants.length === 0 || tenantsWithoutMfa.length === 0) ? undefined : {
        description: 'Tenants without MFA expose end-users to credential theft.',
        affected_resources: tenantsWithoutMfa.map<AffectedResource>((t: any) => ({ type: 'google_identity_platform_tenant', identifier: t.name, attributes: { mfaConfig: t.mfaConfig } })),
      },
      remediation: (identityPlatformTenants.length === 0 || tenantsWithoutMfa.length === 0) ? undefined : {
        summary: 'Set mfaConfig.state=ENFORCED on each tenant. Coordinate end-user comms.',
        options: [{
          approach: 'Enforce MFA on tenants via Terraform — same as KSI-IAM-MFA Finding 4.',
          mechanism: 'terraform',
          owner_team: 'Product',
          cost_impact: { level: 'low', notes: 'Identity Platform per-MAU charges; MFA may slightly increase.' },
          availability_impact: { level: 'medium', notes: 'End-users challenged to enroll on next sign-in.' },
          customer_visible: { level: 'high', notes: 'Agency end-users see new MFA enrollment flow.' },
          effort_estimate: { magnitude: 'days', notes: 'Config quick; comms is the work.' },
          steps: ['Decide allowed factors (TOTP/WebAuthn preferred; SMS allowed but not phishing-resistant).', 'Apply Terraform.', 'Communicate to end-users.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-2','ia-2.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Identity Platform tenant MFA also satisfies MFA KSI for end-users.' },
        { ksi_id: 'KSI-AFR-SCG', relationship: 'shares-remediation', note: 'Document MFA enrollment guidance in the customer-facing SCG.' },
      ],
      note: identityPlatformTenants.length === 0 ? 'Identity Platform not in use — passes vacuously.' : undefined,
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-ELP — Least Privilege
// =====================================================================
export async function collectIamElp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Project IAM policy: scan for primitive roles
  const primitiveBindings: Array<{ role: string; members: string[] }> = [];
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({ resource: `projects/${ctx.project}`, requestBody: { options: { requestedPolicyVersion: 3 } } });
    const policy = r.data;
    for (const b of policy.bindings ?? []) {
      if (b.role === 'roles/owner' || b.role === 'roles/editor' || b.role === 'roles/viewer') {
        primitiveBindings.push({ role: b.role, members: b.members ?? [] });
      }
    }
    evidence.push(ev('cloudresourcemanager.projects.getIamPolicy', { bindings: policy.bindings?.length ?? 0, primitive_bindings: primitiveBindings }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy', 'resourcemanager.projects.getIamPolicy (roles/resourcemanager.projectIamAdmin or roles/viewer)'));
  }

  // Recommender: over-privilege (same as AAM, but tagged ELP)
  let recCount = 0;
  try {
    const recommender = await gcpAuth.googleClient<any>('recommender', 'v1');
    const parent = `projects/${ctx.project}/locations/global/recommenders/google.iam.policy.Recommender`;
    const r = await recommender.projects.locations.recommenders.recommendations.list({ parent, pageSize: 100 });
    recCount = r.data.recommendations?.length ?? 0;
    evidence.push(ev('recommender.policy_recommendations', { count: recCount }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'recommender.iam.policy.Recommender.list', 'recommender.*.list (roles/recommender.viewer)'));
  }

  const findings = [
    finding({
      rule: 'gcp.iam.no_primitive_roles_on_project',
      passed: primitiveBindings.length === 0,
      severity: 'high',
      current: {
        summary: primitiveBindings.length === 0
          ? 'No primitive role (roles/owner|editor|viewer) bindings on the project.'
          : `${primitiveBindings.length} primitive role binding(s) found on the project — these grant broad access and should be replaced with predefined or custom roles.`,
        observations: { primitive_bindings: primitiveBindings },
      },
      target: { summary: 'No primitive role bindings on prod projects.', rationale: 'NIST AC-6 least privilege. Primitive roles grant broad access and don\'t support fine-grained NIST control mappings.' },
      gap: primitiveBindings.length === 0 ? undefined : {
        description: 'Each primitive binding is a broad grant. Identify each member and demote to a specific predefined role.',
        affected_resources: primitiveBindings.map<AffectedResource>((b) => ({
          type: 'google_project_iam_binding', identifier: `${ctx.project}/${b.role}`, name: b.role,
          attributes: { members: b.members },
        })),
      },
      remediation: primitiveBindings.length === 0 ? undefined : {
        summary: 'Replace each primitive binding with the minimum predefined / custom role that meets the member\'s actual usage.',
        options: [{
          approach: 'Run Policy Analyzer to find actual usage; demote bindings via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Tightening roles can break access. Use Policy Analyzer reports.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per-member analysis + IaC update.' },
          steps: [
            'Use Policy Analyzer (gcloud asset analyze-iam-policy) to see what each member actually does.',
            'Identify the minimum predefined role that covers usage.',
            'Update Terraform bindings.',
            'Apply; monitor logs for permission errors.',
          ],
          example_code: `# Replace this:
# resource "google_project_iam_member" "alice_owner" {
#   project = var.project_id
#   role    = "roles/owner"
#   member  = "user:alice@example.com"
# }
# With:
resource "google_project_iam_member" "alice_editor_scoped" {
  project = var.project_id
  role    = "roles/run.developer"   # scoped to actual usage
  member  = "user:alice@example.com"
}`,
          references: [{ title: 'GCP docs: IAM Policy Analyzer', url: 'https://cloud.google.com/policy-intelligence/docs/policy-analyzer-overview' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','ac-6.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Group-driven IAM (AAM) is the structural prerequisite.' },
      ],
    }),

    finding({
      rule: 'gcp.recommender.policy_recommendations_below_threshold',
      passed: recCount <= 25,
      severity: 'medium',
      current: { summary: `${recCount} over-privilege recommendation(s) from IAM Recommender.`, observations: { recCount } },
      target: { summary: 'Policy recommendations ≤ 25, trending down.', rationale: 'Recommender catches over-grants automatically; high counts indicate stale grants.' },
      gap: recCount <= 25 ? undefined : {
        description: 'High recommendation count indicates persistent over-grants.',
        affected_resources: [{ type: 'google_recommender_recommendation', identifier: 'policy.Recommender', attributes: { count: recCount } }],
      },
      remediation: recCount <= 25 ? undefined : {
        summary: 'Apply Recommender suggestions in IaC; document any dismissed.',
        options: [{
          approach: 'Bulk-apply Recommender suggestions.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Removing roles can break consumers; pilot one.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Triage + IaC update + canary.' },
          steps: ['Export recommendations via API.', 'For each: apply / dismiss / defer.', 'Apply; monitor for permission errors.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Same review cadence.' },
      ],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'gcp',
    third_party_tools_detected: thirdParty,
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
  };
}

// =====================================================================
// KSI-IAM-JIT — Just-in-Time
// =====================================================================
export async function collectIamJit(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Look for conditional IAM bindings (time-bound)
  let conditionalBindingCount = 0;
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({
      resource: `projects/${ctx.project}`,
      requestBody: { options: { requestedPolicyVersion: 3 } },
    });
    const policy = r.data;
    conditionalBindingCount = (policy.bindings ?? []).filter((b: any) => !!b.condition).length;
    evidence.push(ev('cloudresourcemanager.projects.getIamPolicy.conditions', { conditional_binding_count: conditionalBindingCount }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy (conditions)', 'resourcemanager.projects.getIamPolicy (roles/resourcemanager.projectIamAdmin or roles/viewer)'));
  }

  // PAM entitlements (GA 2024). Not all projects have PAM enabled; treat absence as warning.
  let pamEntitlementCount = 0;
  try {
    const pam = await gcpAuth.googleClient<any>('privilegedaccessmanager', 'v1');
    // Entitlements live at projects/{p}/locations/global/entitlements
    const r = await pam.projects.locations.entitlements.list({ parent: `projects/${ctx.project}/locations/global`, pageSize: 50 });
    pamEntitlementCount = r.data.entitlements?.length ?? 0;
    evidence.push(ev('privilegedaccessmanager.entitlements', { count: pamEntitlementCount }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'privilegedaccessmanager.projects.locations.entitlements.list', 'privilegedaccessmanager.entitlements.list (roles/privilegedaccessmanager.viewer)'));
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party JIT tool (Teleport, ConductorOne, StrongDM, etc.)',
      description: 'JIT can be implemented via a 3rd-party tool that issues short-lived GCP tokens through impersonation or WIF.',
      evidence_required: ['JIT tool admin audit log export', 'SA impersonation bindings showing the tool principal', 'Sample grant + revoke event'],
      detected: false,
      detection_signals: ['Will populate from third_party_tools_detected after enumeration'],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.pam.entitlements_present',
      passed: pamEntitlementCount >= 1,
      severity: 'medium',
      current: {
        summary: pamEntitlementCount >= 1
          ? `${pamEntitlementCount} Privileged Access Manager entitlement(s) configured — native JIT in place.`
          : 'No PAM entitlements (PAM not enabled or no permission to read).',
        observations: { pamEntitlementCount },
      },
      target: { summary: 'At least one PAM entitlement covers privileged roles (e.g. roles/owner, roles/iam.securityAdmin).', rationale: 'PAM is GCP-native JIT; entitlements drive grant + auto-revoke + audit.' },
      gap: pamEntitlementCount >= 1 ? undefined : {
        description: 'Without PAM entitlements, privileged access is either permanently granted (anti-pattern) or governed by a 3rd-party tool whose evidence lives elsewhere.',
        affected_resources: [{ type: 'google_privileged_access_manager_entitlement', identifier: 'none', attributes: {} }],
      },
      remediation: pamEntitlementCount >= 1 ? undefined : {
        summary: 'Enable PAM and define entitlements for break-glass + sensitive roles.',
        options: [{
          approach: 'Configure PAM entitlements via Terraform / gcloud.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'PAM is included with most enterprise tiers; pricing varies.' },
          availability_impact: { level: 'low', notes: 'PAM is opt-in per entitlement; existing permanent bindings keep working.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Initial entitlement modeling + IAM cleanup.' },
          steps: [
            'Enable Privileged Access Manager API.',
            'Define entitlements covering break-glass / admin roles.',
            'Configure approval workflows (one-approver or two-approver).',
            'Remove the underlying permanent IAM bindings for the role; users now request via PAM.',
            'Test the request → approve → use → expire flow.',
          ],
          references: [{ title: 'GCP docs: Privileged Access Manager', url: 'https://cloud.google.com/iam/docs/pam-overview' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ac-2','ac-6.7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'depends-on', note: 'JIT is meaningful only on a least-privilege baseline.' },
      ],
    }),

    finding({
      rule: 'gcp.iam.conditional_bindings_present',
      passed: conditionalBindingCount >= 1,
      severity: 'medium',
      current: {
        summary: conditionalBindingCount >= 1
          ? `${conditionalBindingCount} conditional IAM binding(s) found — supports time-bound or attribute-bound access.`
          : 'No conditional IAM bindings — all access is permanent until removed.',
        observations: { conditionalBindingCount },
      },
      target: { summary: 'At least one conditional binding uses request.time expiry or attribute conditions for privileged roles.', rationale: 'Conditional bindings are a lightweight JIT primitive when PAM is not in use.' },
      gap: conditionalBindingCount >= 1 ? undefined : {
        description: 'Without conditional bindings, all role grants are permanent. Either use PAM (preferred) or add time-bound conditions to privileged bindings.',
        affected_resources: [{ type: 'google_project_iam_binding', identifier: ctx.project, attributes: { conditional_bindings: 0 } }],
      },
      remediation: conditionalBindingCount >= 1 ? undefined : {
        summary: 'Add time-bound conditions to privileged role bindings.',
        options: [{
          approach: 'Convert privileged bindings to conditional bindings via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Once expired, members must re-request via approver.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-binding analysis.' },
          steps: [
            'Identify privileged bindings (roles/owner, roles/iam.securityAdmin, etc.).',
            'Decide expiry duration (typically 30/60/90 days).',
            'Add request.time condition to each binding.',
            'Schedule a renewal review before expiry.',
          ],
          example_code: `resource "google_project_iam_binding" "break_glass_admin" {
  project = var.project_id
  role    = "roles/owner"
  members = ["group:break-glass@example.com"]
  condition {
    title       = "Break-glass valid for 4 hours"
    expression  = "request.time < timestamp(\\"2026-12-31T23:59:59Z\\")"
  }
}`,
          references: [{ title: 'GCP docs: IAM conditions', url: 'https://cloud.google.com/iam/docs/conditions-overview' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ac-2','ac-6.7'],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});
  const jitToolDetected = thirdParty.some((t) => /Teleport|ConductorOne|StrongDM/.test(t.name));
  if (jitToolDetected) {
    altSatisfiers[0]!.detected = true;
    altSatisfiers[0]!.detection_signals = thirdParty.filter((t) => /Teleport|ConductorOne|StrongDM/.test(t.name)).flatMap((t) => t.detection_signals);
  }

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-MFA — Phishing-Resistant MFA
// REFERENCE IMPLEMENTATION of the v2 rich-evidence schema.
// =====================================================================
export async function collectIamMfa(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---- Org policy: iam.allowedPolicyMemberDomains ----
  // If enforced, all IAM principals come from a managed domain — and that
  // domain's IdP is responsible for MFA enforcement.
  let allowedDomainsConstraint: any = null;
  let allowedDomainsEnforced = false;
  try {
    const orgpolicy = await gcpAuth.googleClient<any>('orgpolicy', 'v2');
    try {
      const got = await orgpolicy.projects.policies.get({
        name: `projects/${ctx.project}/policies/iam.allowedPolicyMemberDomains`,
      });
      allowedDomainsConstraint = got.data;
      allowedDomainsEnforced = (got.data.spec?.rules ?? []).some((r: any) => r.values?.allowedValues?.length > 0);
      evidence.push(ev('orgpolicy.iam.allowedPolicyMemberDomains', got.data));
    } catch (e) {
      warnings.push(diagnoseGcpError(e, 'orgpolicy.projects.policies.get (iam.allowedPolicyMemberDomains)', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)'));
    }
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'orgpolicy.googleClient', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)'));
  }

  // ---- IAM bindings: any direct `user:` principals (vs groups + workforce pools)? ----
  interface DirectUserBinding { role: string; member: string; condition?: any; }
  const directUserBindings: DirectUserBinding[] = [];
  let totalBindings = 0;
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({
      resource: `projects/${ctx.project}`,
      requestBody: { options: { requestedPolicyVersion: 3 } },
    });
    const policy = r.data;
    for (const b of policy.bindings ?? []) {
      totalBindings++;
      for (const m of b.members ?? []) {
        if (m.startsWith('user:')) {
          directUserBindings.push({ role: b.role, member: m, condition: b.condition });
        }
      }
    }
    evidence.push(ev('cloudresourcemanager.iam_bindings_users_only', {
      total_bindings: totalBindings,
      direct_user_principals: directUserBindings,
    }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy', 'resourcemanager.projects.getIamPolicy (roles/resourcemanager.projectIamAdmin or roles/viewer)'));
  }

  // ---- Access Context Manager (CAA) — access levels can restrict MFA factor ----
  interface AccessLevelRecord { policy: string; level: string; basicSpec: any; }
  const accessLevels: AccessLevelRecord[] = [];
  let accessPolicies: any[] = [];
  try {
    const acm = await gcpAuth.googleClient<any>('accesscontextmanager', 'v1');
    const policies = await acm.accessPolicies.list({});
    accessPolicies = policies.data.accessPolicies ?? [];
    for (const ap of accessPolicies) {
      try {
        const levels = await acm.accessPolicies.accessLevels.list({ parent: ap.name, pageSize: 50 });
        for (const lvl of levels.data.accessLevels ?? []) {
          accessLevels.push({ policy: ap.name, level: lvl.name, basicSpec: lvl.basic });
        }
      } catch (e) {
        warnings.push(diagnoseGcpError(e, `accesscontextmanager.accessPolicies.accessLevels.list (${ap.name})`, 'accesscontextmanager.accessLevels.list (roles/accesscontextmanager.policyReader)'));
      }
    }
    evidence.push(ev('accesscontextmanager.full_inventory', { policies: accessPolicies, levels: accessLevels }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'accesscontextmanager.accessPolicies.list', 'accesscontextmanager.accessPolicies.list (roles/accesscontextmanager.policyReader)'));
  }

  // ---- Identity Platform tenants (app-user IdP, if used) ----
  let identityPlatformTenants: any[] = [];
  try {
    const itp = await gcpAuth.googleClient<any>('identitytoolkit', 'v2');
    const r = await itp.projects.tenants.list({ parent: `projects/${ctx.project}`, pageSize: 50 });
    identityPlatformTenants = r.data.tenants ?? [];
    evidence.push(ev('identitytoolkit.tenants.list', identityPlatformTenants.map((t: any) => ({
      name: t.name,
      displayName: t.displayName,
      mfaConfig: t.mfaConfig,
      enableEmailLinkSignin: t.enableEmailLinkSignin,
    }))));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'identitytoolkit.projects.tenants.list', 'identitytoolkit.tenants.list (roles/identitytoolkit.viewer or roles/firebaseauth.viewer)'));
  }

  // ---- Workforce Identity Federation pools (alternative-satisfier detection) ----
  let workforcePoolCount = 0;
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    const r = await iam.projects.locations.workforcePools?.list({ parent: 'locations/global', pageSize: 50 });
    workforcePoolCount = r?.data?.workforcePools?.length ?? 0;
    evidence.push(ev('iam.locations.workforcePools.list', { count: workforcePoolCount }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'iam.projects.locations.workforcePools.list', 'iam.workforcePools.list (roles/iam.workforcePoolViewer)'));
  }

  // ---- Compose alternative satisfiers ----
  const externalIdpDetected = workforcePoolCount > 0 || allowedDomainsEnforced;
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External IdP (Okta, Azure AD, Google Workspace acting as primary IdP)',
      description: 'When all human access is federated through an external IdP, MFA enforcement is the IdP\'s responsibility. GCP-side checks become secondary to the upstream IdP\'s MFA policy.',
      evidence_required: [
        'IdP MFA enforcement policy (Okta Authentication Policy, Azure AD Conditional Access, Workspace 2SV settings)',
        'List of users / groups in scope of the GCP access integration',
        'Sample sign-in log showing WebAuthn / security key was used',
      ],
      detected: externalIdpDetected,
      detection_signals: [
        ...(workforcePoolCount > 0 ? [`Workforce Identity Federation pools: ${workforcePoolCount}`] : []),
        ...(allowedDomainsEnforced ? ['iam.allowedPolicyMemberDomains constraint is enforced (managed-domain principals only)'] : []),
        ...(externalIdpDetected ? [] : ['No WIF pools; no allowedPolicyMemberDomains constraint. GCP appears to be managing identity directly.']),
      ],
    },
    {
      via: 'Workspace / Cloud Identity 2SV enforced via Admin Console',
      description: 'Workspace / Cloud Identity enforces 2SV with security keys for all users. The Workspace Admin SDK can attest this but requires a delegated admin OAuth scope that ADC may not have.',
      evidence_required: [
        'Workspace Admin Console screenshot showing 2SV enforcement with allowed factor restriction to security keys',
        'Export of users not yet enrolled in 2SV (should be 0 for in-scope users)',
      ],
      detected: false,
      detection_signals: ['Workspace Admin SDK requires admin OAuth scope; not collected from ADC. Confirm manually.'],
    },
  ];

  // ---- Findings ----

  const tenantsWithoutMfa = identityPlatformTenants.filter((t: any) => t.mfaConfig?.state !== 'ENFORCED');

  const findings = [
    // ----- Finding 1: Managed-domain enforcement -----
    finding({
      rule: 'gcp.org.allowed_policy_member_domains_enforced',
      passed: allowedDomainsEnforced,
      severity: 'high',
      current: {
        summary: allowedDomainsEnforced
          ? 'iam.allowedPolicyMemberDomains is enforced on this project — only principals from approved domains can be granted IAM.'
          : 'iam.allowedPolicyMemberDomains constraint is NOT enforced. Any external email (e.g. @gmail.com) could be granted IAM access.',
        observations: allowedDomainsConstraint,
      },
      target: {
        summary: 'allowedPolicyMemberDomains is enforced at org or project, restricting IAM members to a list of managed Cloud Identity / Workspace customer IDs.',
        rationale: 'Blocks accidental external grants and ensures every principal is governed by the org\'s IdP MFA policy. Tightens the trust boundary for phishing-resistant MFA.',
      },
      gap: allowedDomainsEnforced ? undefined : {
        description: 'Without this constraint, an admin could grant `roles/owner` to an external `@gmail.com` identity bypassing the org\'s MFA enforcement entirely.',
        affected_resources: [{
          type: 'google_org_policy_policy',
          identifier: `projects/${ctx.project}/policies/iam.allowedPolicyMemberDomains`,
          attributes: { current_spec: allowedDomainsConstraint?.spec },
        }],
      },
      remediation: allowedDomainsEnforced ? undefined : {
        summary: 'Enforce iam.allowedPolicyMemberDomains with your Workspace/Cloud Identity customer ID(s) at the organization level.',
        options: [
          {
            approach: 'Apply at org level (preferred — propagates to all projects).',
            mechanism: 'terraform',
            owner_team: 'Security',
            cost_impact: { level: 'none', notes: 'GCP Organization Policy is free.' },
            availability_impact: { level: 'medium', notes: 'Existing external-domain bindings start failing — audit first via the org-policy dry-run mode.' },
            customer_visible: { level: 'none', notes: 'Internal control-plane policy.' },
            effort_estimate: { magnitude: 'days', notes: 'Stage in a test folder; audit existing bindings; gradual roll-forward.' },
            prerequisites: [
              'Know your Cloud Identity customer ID(s): see Workspace Admin > Account settings > Customer ID.',
              'Apply from a principal with `roles/orgpolicy.policyAdmin` on the org.',
            ],
            example_code: `resource "google_org_policy_policy" "allowed_domains" {
  name   = "organizations/$\${var.org_id}/policies/iam.allowedPolicyMemberDomains"
  parent = "organizations/$\${var.org_id}"
  spec {
    rules {
      values {
        allowed_values = [
          "C0xxxxxxx",          # your Cloud Identity customer ID
          # additional customer IDs if you have multiple Workspace tenants
        ]
      }
    }
  }
}`,
            steps: [
              'Locate the Cloud Identity customer ID(s).',
              'Apply the org policy at the organization level.',
              'Test in a non-prod folder first: try to add an external user to a project — should be denied.',
              'Roll forward to all folders.',
            ],
            side_effects: [
              'Existing external-domain bindings will be flagged in the org policy violations list.',
              'IaC pipelines that grant access to vendor accounts must be updated to grant via service accounts instead.',
            ],
            references: [
              { title: 'GCP docs: Restrict identities by domain', url: 'https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains' },
            ],
          },
          {
            approach: 'Apply at project level (narrower scope — useful while rolling out).',
            mechanism: 'terraform',
            owner_team: 'Security',
            cost_impact: { level: 'none', notes: 'Free.' },
            availability_impact: { level: 'low', notes: 'Scope limited to one project.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'hours', notes: 'Single-project scope; minimal rollout work.' },
            example_code: `resource "google_org_policy_policy" "project_allowed_domains" {
  name   = "projects/$\${var.project_id}/policies/iam.allowedPolicyMemberDomains"
  parent = "projects/$\${var.project_id}"
  spec {
    rules {
      values {
        allowed_values = ["C0xxxxxxx"]
      }
    }
  }
}`,
            steps: ['Same as above, scoped to a single project.'],
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[1]!],
      nist_controls: ['ac-2','ia-2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Restricting allowed domains is a precondition for clean group-driven IAM (AAM).' },
        { ksi_id: 'KSI-CNA-DFP', relationship: 'shares-remediation', note: 'Org policies are the GCP analog of AWS SCPs — both belong in the DFP guardrail strategy.' },
      ],
    }),

    // ----- Finding 2: Direct user: bindings -----
    finding({
      rule: 'gcp.iam.no_direct_user_bindings',
      passed: directUserBindings.length === 0,
      severity: 'high',
      current: {
        summary: directUserBindings.length === 0
          ? 'No direct user: bindings on the project — IAM is group-driven.'
          : `${directUserBindings.length} direct user: binding(s) on the project. Group-driven IAM is preferred so MFA enforcement remains the IdP\'s responsibility per-user.`,
        observations: { direct_user_bindings: directUserBindings, total_bindings: totalBindings },
      },
      target: {
        summary: 'IAM is granted exclusively via groups (or workforce-pool principals). Individual user: bindings are absent.',
        rationale: 'Direct user: bindings bypass the group lifecycle, so when a user offboards from the IdP, their access can persist. Group-driven IAM ensures the IdP\'s MFA + lifecycle policies are honored.',
      },
      gap: directUserBindings.length === 0 ? undefined : {
        description: 'Each direct user: binding represents a person whose access is not gated by group membership. If their IdP account is deactivated, this binding does not automatically revoke.',
        affected_resources: directUserBindings.map<AffectedResource>((b) => ({
          type: 'google_project_iam_member',
          identifier: `${ctx.project}/${b.role}/${b.member}`,
          attributes: { role: b.role, member: b.member, has_condition: !!b.condition },
        })),
      },
      remediation: directUserBindings.length === 0 ? undefined : {
        summary: 'Migrate each user: binding to a group: binding. Add the user to the appropriate IdP-managed group; remove the user: binding.',
        options: [
          {
            approach: 'Replace user: bindings with group: bindings via Terraform.',
            mechanism: 'terraform',
            owner_team: 'Identity / IT',
            cost_impact: { level: 'none', notes: 'No additional GCP charges.' },
            availability_impact: { level: 'low', notes: 'If the user is already in the target group, no disruption; if not, brief access change during migration.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'hours', notes: 'Quick per user; bulk migration is straightforward.' },
            steps: [
              'In your IdP / Cloud Identity, create or identify the group that represents this access level.',
              'Add the user to the group.',
              'Add a google_project_iam_member binding for the group.',
              'Remove the user: binding.',
            ],
            example_code: `# Add to group: managed in your IdP, not by Terraform.
# Then replace this:
# resource "google_project_iam_member" "user_binding" {
#   project = var.project_id
#   role    = "roles/editor"
#   member  = "user:alice@example.com"
# }
# with:
resource "google_project_iam_member" "group_binding" {
  project = var.project_id
  role    = "roles/editor"
  member  = "group:editors-prod@example.com"
}`,
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ac-2','ac-2.7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Group-driven IAM is the foundation of automated lifecycle (AAM).' },
        { ksi_id: 'KSI-IAM-ELP', relationship: 'precedes', note: 'Groups are the unit of least-privilege role grants.' },
      ],
    }),

    // ----- Finding 3: CAA access level enforcing MFA factor (optional, supporting) -----
    finding({
      rule: 'gcp.access_context_manager.access_levels_present',
      passed: accessLevels.length >= 1,
      severity: 'medium',
      current: {
        summary: accessLevels.length >= 1
          ? `${accessLevels.length} access level(s) configured across ${accessPolicies.length} access policy/policies.`
          : 'No Access Context Manager access levels found. Cannot enforce MFA-factor restriction at the GCP layer.',
        observations: { policies: accessPolicies.map((p) => p.name), levels: accessLevels },
      },
      target: {
        summary: 'At least one Access Context Manager access level restricts session-establishment to phishing-resistant authenticators (security keys).',
        rationale: 'CAA access levels can mandate `device.encryptionStatus.encrypted && session.duration < 1h` and gate prod resources behind IAP / VPC SC perimeters that consume the level. Provides a GCP-side enforcement point that complements the IdP MFA policy.',
      },
      gap: accessLevels.length >= 1 ? undefined : {
        description: 'No CAA access levels exist. MFA enforcement relies entirely on the IdP — if the IdP policy is misconfigured, GCP has no fallback.',
        affected_resources: [{ type: 'google_access_context_manager_access_level', identifier: 'none', attributes: { existing: 0 } }],
      },
      remediation: accessLevels.length >= 1 ? undefined : {
        summary: 'Define an access policy + access level requiring corp-network OR managed-device + recent strong sign-in. Attach to IAP-protected backends or VPC SC service perimeters.',
        options: [
          {
            approach: 'Create access policy + level + IAP attachment via Terraform.',
            mechanism: 'terraform',
            owner_team: 'Security',
            cost_impact: { level: 'low', notes: 'Access Context Manager itself is free; IAP charges per request to protected backends.' },
            availability_impact: { level: 'medium', notes: 'Misconfigured access levels can deny legitimate traffic. Test with a dry-run access level first.' },
            customer_visible: { level: 'none', notes: 'Affects internal access only unless attached to customer-facing IAP.' },
            effort_estimate: { magnitude: 'weeks', notes: 'Modeling access conditions for the org takes time; gradual rollout per backend.' },
            example_code: `resource "google_access_context_manager_access_policy" "this" {
  parent = "organizations/$\${var.org_id}"
  title  = "default"
}
resource "google_access_context_manager_access_level" "strong" {
  parent = "accessPolicies/$\${google_access_context_manager_access_policy.this.name}"
  name   = "accessPolicies/$\${google_access_context_manager_access_policy.this.name}/accessLevels/strong"
  title  = "strong"
  basic {
    conditions {
      required_access_levels = []
      members                = ["group:engineering@example.com"]
      regions                = ["US"]
      ip_subnetworks         = ["203.0.113.0/24"]
      device_policy {
        require_screen_lock = true
        require_corp_owned  = false
        allowed_encryption_statuses = ["ENCRYPTED"]
      }
    }
  }
}`,
            steps: [
              'Create the access policy at the org level.',
              'Define an access level with conditions appropriate to your environment (device posture, geo, group membership).',
              'Attach to IAP-protected resources via google_iap_web_iam_member or to VPC SC perimeters.',
              'Test from an in-scope vs out-of-scope endpoint.',
            ],
            references: [
              { title: 'GCP docs: Access Context Manager', url: 'https://cloud.google.com/access-context-manager/docs/overview' },
            ],
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[1]!],
      nist_controls: ['ac-3','ia-2.1','ia-2.8'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'CAA + VPC Service Controls together constrain attack surface for both MFA and lateral-movement KSIs.' },
      ],
    }),

    // ----- Finding 4: Identity Platform tenants -----
    finding({
      rule: 'gcp.identity_platform.app_user_mfa_enforced',
      passed: tenantsWithoutMfa.length === 0,
      severity: 'high',
      current: {
        summary: identityPlatformTenants.length === 0
          ? 'Identity Platform is not in use (no tenants found). N/A for this KSI on GCP.'
          : (tenantsWithoutMfa.length === 0
            ? 'All Identity Platform tenants have MFA enforced.'
            : `${tenantsWithoutMfa.length} of ${identityPlatformTenants.length} Identity Platform tenants do not enforce MFA.`),
        observations: identityPlatformTenants.map((t) => ({ name: t.name, displayName: t.displayName, mfaConfig: t.mfaConfig })),
      },
      target: {
        summary: 'If Identity Platform is used to authenticate app users, every tenant enforces MFA.',
        rationale: 'Application end-users (federal customer end-users in your SaaS) need MFA per FedRAMP requirements.',
      },
      gap: tenantsWithoutMfa.length === 0 ? undefined : {
        description: 'Identity Platform tenants without MFA enforcement let federal end-users sign in with passwords only.',
        affected_resources: tenantsWithoutMfa.map<AffectedResource>((t: any) => ({
          type: 'google_identity_platform_tenant',
          identifier: t.name,
          name: t.displayName ?? t.name,
          attributes: { mfaConfig: t.mfaConfig },
        })),
      },
      remediation: tenantsWithoutMfa.length === 0 ? undefined : {
        summary: 'Enable MFA enforcement on each tenant via the Identity Toolkit Tenant.update API or Console.',
        options: [
          {
            approach: 'Enforce MFA on each tenant via Terraform.',
            mechanism: 'terraform',
            owner_team: 'Product',
            cost_impact: { level: 'low', notes: 'Identity Platform charges per MAU; MFA enrollment may slightly increase per-user costs.' },
            availability_impact: { level: 'medium', notes: 'Existing end-users without MFA will be challenged to enroll on next sign-in — coordinate with product team.' },
            customer_visible: { level: 'high', notes: 'Agency / app end users see a new MFA enrollment flow. Communicate beforehand.' },
            effort_estimate: { magnitude: 'days', notes: 'Tenant-level configuration is quick; end-user communication + support is the long tail.' },
            example_code: `resource "google_identity_platform_tenant" "main" {
  display_name              = "Main"
  allow_password_signup     = true
  mfa_config {
    state            = "ENFORCED"
    enabled_providers = ["PHONE_SMS"]  # SMS is NOT phishing-resistant; prefer TOTP or WebAuthn via Firebase Auth
  }
}`,
            steps: [
              'Update each tenant\'s mfaConfig.state to ENFORCED.',
              'Validate enabled_providers — prefer TOTP / WebAuthn. SMS is allowed but is not phishing-resistant.',
              'Test sign-in flow.',
            ],
            side_effects: [
              'Existing users without MFA enrolled will be prompted to enroll on next sign-in.',
            ],
            references: [
              { title: 'Identity Platform multi-factor authentication', url: 'https://cloud.google.com/identity-platform/docs/multi-factor-authentication' },
            ],
          },
        ],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-2','ia-2.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-AFR-SCG', relationship: 'shares-remediation', note: 'Identity Platform end-user MFA settings should be documented in the Secure Configuration Guide for agency customers.' },
      ],
      note: identityPlatformTenants.length === 0 ? 'Identity Platform not in use — this finding passes vacuously.' : undefined,
    }),
  ];

  // ---- 3rd-party tool detection ----
  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    workforce_pool_count: workforcePoolCount,
    workforce_pool_providers: [], // expand when we enumerate WIF providers in later phase
    iam_members: directUserBindings.map((b) => b.member),
    service_account_emails: [], // populated by IAM-AAM/SNU collectors
  });

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-SNU — Non-User Authentication
// =====================================================================
export async function collectIamSnu(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Service accounts with user-managed keys (anti-pattern)
  let saWithUserKeys = 0;
  const offendingSas: string[] = [];
  let saTotal = 0;
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    const sas = await iam.projects.serviceAccounts.list({ name: `projects/${ctx.project}`, pageSize: 100 });
    const accounts = sas.data.accounts ?? [];
    saTotal = accounts.length;
    for (const sa of accounts) {
      try {
        const kr = await iam.projects.serviceAccounts.keys.list({ name: sa.name, keyTypes: ['USER_MANAGED'] });
        const userKeys = kr.data.keys?.length ?? 0;
        if (userKeys > 0) {
          saWithUserKeys++;
          offendingSas.push(`${sa.email}: ${userKeys} key(s)`);
        }
      } catch (e) {
        warnings.push(diagnoseGcpError(e, `iam.projects.serviceAccounts.keys.list (${sa.email})`, 'iam.serviceAccountKeys.list (roles/iam.serviceAccountViewer)'));
      }
    }
    evidence.push(ev('iam.projects.serviceAccounts.keys.list', { sa_total: saTotal, sa_with_user_keys: saWithUserKeys, offenders: offendingSas }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'iam.projects.serviceAccounts.list', 'iam.serviceAccounts.list (roles/iam.serviceAccountViewer)'));
  }

  // Workload Identity Federation pools (org-level)
  let wifPoolCount = 0;
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    const r = await iam.projects.locations.workloadIdentityPools.list({ parent: `projects/${ctx.project}/locations/global`, pageSize: 50 });
    wifPoolCount = r.data.workloadIdentityPools?.length ?? 0;
    evidence.push(ev('iam.projects.locations.workloadIdentityPools.list', { count: wifPoolCount }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'iam.projects.locations.workloadIdentityPools.list', 'iam.workloadIdentityPools.list (roles/iam.workloadIdentityPoolViewer)'));
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'HashiCorp Vault gcp secret engine or other secret broker',
      description: 'Vault\'s GCP secret engine issues short-lived SA tokens on demand, eliminating static SA keys.',
      evidence_required: ['Vault config showing GCP secret engine bound to short TTL', 'Sample audit log of dynamic SA token issuance'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.sa.no_user_managed_keys',
      passed: offendingSas.length === 0,
      severity: 'high',
      current: {
        summary: offendingSas.length === 0
          ? `No service accounts (out of ${saTotal}) have user-managed keys.`
          : `${offendingSas.length} of ${saTotal} service account(s) have user-managed keys.`,
        observations: { sa_total: saTotal, offenders: offendingSas },
      },
      target: { summary: 'Zero user-managed SA keys. All SAs authenticate via short-lived tokens (WIF, GKE Workload Identity, GCE identity, impersonation).', rationale: 'NIST IA-5(1). User-managed keys are long-lived; if leaked, full SA compromise.' },
      gap: offendingSas.length === 0 ? undefined : {
        description: 'Each user-managed key represents a long-lived secret stored somewhere downstream.',
        affected_resources: offendingSas.map<AffectedResource>((s) => ({
          type: 'google_service_account_key', identifier: s, attributes: {},
        })),
      },
      remediation: offendingSas.length === 0 ? undefined : {
        summary: 'Migrate each SA from user-managed key auth to WIF or impersonation.',
        options: [{
          approach: 'Workload Identity Federation for off-GCP workloads (CI/CD, AWS, Azure, on-prem).',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'WIF is free.' },
          availability_impact: { level: 'medium', notes: 'Per-workload migration.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per workload.' },
          steps: [
            'Create a workload identity pool + provider for the external IdP.',
            'Grant pool principal access to the target SA via roles/iam.workloadIdentityUser.',
            'Update workload to use the WIF flow.',
            'Delete the user-managed key.',
          ],
          example_code: `# See KSI-IAM-AAM Finding 1 remediation for the full Terraform.`,
          references: [{ title: 'GCP docs: WIF', url: 'https://cloud.google.com/iam/docs/workload-identity-federation' }],
        }, {
          approach: 'GKE Workload Identity for in-cluster workloads.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Per-namespace migration.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Cluster setup + per-namespace.' },
          steps: ['Enable Workload Identity on cluster.', 'Annotate K8s SA with GCP SA email.', 'Bind via roles/iam.workloadIdentityUser.', 'Delete user-managed keys.'],
          references: [{ title: 'GKE Workload Identity', url: 'https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ia-5','ia-5.1','ia-9'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Same migration effort.' },
        { ksi_id: 'KSI-SVC-ASM', relationship: 'shares-remediation', note: 'Eliminates static credentials from secret stores.' },
      ],
    }),

    finding({
      rule: 'gcp.workload_identity_federation.pool_configured',
      passed: wifPoolCount >= 1,
      severity: 'medium',
      current: {
        summary: wifPoolCount >= 1
          ? `${wifPoolCount} Workload Identity Federation pool(s) configured.`
          : 'No WIF pools configured.',
        observations: { wifPoolCount },
      },
      target: { summary: 'At least one WIF pool exists for non-GCP workloads (CI/CD, off-cloud).', rationale: 'WIF eliminates the need for SA JSON keys for off-cloud workloads.' },
      gap: wifPoolCount >= 1 ? undefined : {
        description: 'Off-GCP workloads must use SA keys without WIF — anti-pattern.',
        affected_resources: [{ type: 'google_iam_workload_identity_pool', identifier: 'none', attributes: {} }],
      },
      remediation: wifPoolCount >= 1 ? undefined : {
        summary: 'Stand up a WIF pool for your main external workload source.',
        options: [{
          approach: 'Configure WIF pool + provider for GitHub Actions / other IdP.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Net-new.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Setup + per-workload migration.' },
          steps: ['Create pool + provider.', 'Grant pool access to target SAs.', 'Migrate workloads.', 'Delete legacy SA keys.'],
          references: [{ title: 'WIF', url: 'https://cloud.google.com/iam/docs/workload-identity-federation' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-9'],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-SUS — Responding to Suspicious Activity
// =====================================================================
export async function collectIamSus(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // SCC notification configs require org-level SCC. Skipped at project scope.
  // Eventarc triggers at project level: list and surface any consuming security findings.
  let eventarcTriggers = 0;
  let securityTriggers: string[] = [];
  try {
    const eventarc = await gcpAuth.googleClient<any>('eventarc', 'v1');
    const r = await eventarc.projects.locations.triggers.list({ parent: `projects/${ctx.project}/locations/-`, pageSize: 100 });
    const triggers = r.data.triggers ?? [];
    eventarcTriggers = triggers.length;
    for (const t of triggers) {
      const filters = JSON.stringify(t.eventFilters ?? []);
      if (/securitycenter|cloud\.audit\.AuditLog/i.test(filters)) {
        securityTriggers.push(t.name);
      }
    }
    evidence.push(ev('eventarc.projects.locations.triggers.list', { total: eventarcTriggers, security_related: securityTriggers }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'eventarc.projects.locations.triggers.list', 'eventarc.triggers.list (roles/eventarc.viewer)'));
  }

  // Cloud Audit Logs config — Data Access logging on for sensitive services?
  let dataAccessLoggingForKmsIam = false;
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({ resource: `projects/${ctx.project}`, requestBody: { options: { requestedPolicyVersion: 3 } } });
    const auditConfigs = r.data.auditConfigs ?? [];
    const services = new Set<string>();
    for (const ac of auditConfigs) {
      const types = (ac.auditLogConfigs ?? []).map((l: any) => l.logType);
      if (types.includes('DATA_READ') && types.includes('DATA_WRITE')) {
        services.add(ac.service);
      }
    }
    dataAccessLoggingForKmsIam = services.has('cloudkms.googleapis.com') && services.has('iam.googleapis.com');
    evidence.push(ev('cloudresourcemanager.audit_configs', { services_with_full_data_logging: Array.from(services) }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy', 'resourcemanager.projects.getIamPolicy (roles/resourcemanager.projectIamAdmin or roles/viewer)'));
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party SOAR / SIEM with auto-response',
      description: 'SCC findings can be consumed by an external SOAR (Tines, Torq, Splunk SOAR, Chronicle SOAR) which executes the response.',
      evidence_required: ['SOAR playbook export', 'Sample execution log', 'SCC notification config routing to SOAR-consumed Pub/Sub topic'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.eventarc.security_triggers_present',
      passed: securityTriggers.length >= 1,
      severity: 'high',
      current: {
        summary: securityTriggers.length >= 1
          ? `${securityTriggers.length} Eventarc trigger(s) consume security-related events.`
          : 'No Eventarc triggers consume security events. Detection without automated response.',
        observations: { eventarc_total: eventarcTriggers, security_related: securityTriggers },
      },
      target: { summary: 'At least one Eventarc trigger routes SCC findings (or Cloud Audit Log events for IAM anomalies) to a Cloud Function that responds.', rationale: 'KSI-IAM-SUS requires AUTOMATIC disable/secure. NIST IR-4.' },
      gap: securityTriggers.length >= 1 ? undefined : {
        description: 'Without an automated response trigger, every alert requires human intervention.',
        affected_resources: [{ type: 'google_eventarc_trigger', identifier: 'none-for-security', attributes: {} }],
      },
      remediation: securityTriggers.length >= 1 ? undefined : {
        summary: 'Wire SCC findings → Pub/Sub → Cloud Function for IAM credential compromise response.',
        options: [{
          approach: 'Configure SCC notification + Eventarc + responder.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Eventarc + Cloud Functions invocations are minimal at finding volumes. SCC Premium tier has additional cost if not already on.' },
          availability_impact: { level: 'medium', notes: 'Auto-disable on false positives. Pilot in notify-only mode.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Build responder + tune false positives.' },
          steps: [
            'Configure SCC notification config to publish IAM-anomaly findings to a Pub/Sub topic.',
            'Create an Eventarc trigger consuming that topic; invoke a Cloud Function.',
            'Function disables the affected SA / revokes session.',
            'Pilot in notify-only mode for 2-4 weeks; promote to auto-disable for high-confidence findings.',
          ],
          example_code: `resource "google_pubsub_topic" "scc_findings" { name = "scc-iam-findings" }
resource "google_scc_notification_config" "iam_findings" {
  config_id    = "iam-anomalous-grant"
  organization = var.org_id
  pubsub_topic = google_pubsub_topic.scc_findings.id
  streaming_config {
    filter = "category=\\"IAM_ANOMALOUS_GRANT\\" OR category=\\"PERSISTENCE: IAM Anomalous Grant\\""
  }
}`,
          references: [{ title: 'SCC notifications', url: 'https://cloud.google.com/security-command-center/docs/how-to-notifications' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ir-4','si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-INR-RIR', relationship: 'shares-remediation', note: 'Same plumbing serves IR procedures.' },
      ],
    }),

    finding({
      rule: 'gcp.audit.data_access_logging_on_kms_and_iam',
      passed: dataAccessLoggingForKmsIam,
      severity: 'high',
      current: {
        summary: dataAccessLoggingForKmsIam
          ? 'Data Access logging is enabled for cloudkms.googleapis.com AND iam.googleapis.com — full visibility into IAM + crypto operations.'
          : 'Data Access logging is NOT enabled for cloudkms.googleapis.com AND iam.googleapis.com — suspicious-activity signals on those services are blind.',
        observations: { dataAccessLoggingForKmsIam },
      },
      target: { summary: 'DATA_READ + DATA_WRITE enabled for cloudkms, iam, secretmanager, storage at minimum.', rationale: 'NIST AU-2, SI-4. Without these logs, IAM modifications + secret reads are unobservable.' },
      gap: dataAccessLoggingForKmsIam ? undefined : {
        description: 'Default GCP audit config does NOT log Data Access for any service. Suspicious-activity automation is blind without it.',
        affected_resources: [{ type: 'google_project_iam_audit_config', identifier: ctx.project, attributes: {} }],
      },
      remediation: dataAccessLoggingForKmsIam ? undefined : {
        summary: 'Enable Data Access logging for sensitive services via Terraform.',
        options: [{
          approach: 'Configure audit_config blocks via google_project_iam_audit_config.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Data Access logs are billed at standard Cloud Logging rates. For SaaS workloads, expect $tens-hundreds/month.' },
          availability_impact: { level: 'none', notes: 'No availability impact — purely additive logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform; verify in Cloud Logging.' },
          steps: [
            'Apply audit_config blocks for cloudkms, iam, secretmanager, storage.',
            'Wait ~15 minutes; verify logs appearing in Cloud Logging.',
            'Update the SIEM ingestion to consume the new event types.',
          ],
          example_code: `resource "google_project_iam_audit_config" "kms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
resource "google_project_iam_audit_config" "iam" {
  project = var.project_id
  service = "iam.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}`,
          references: [{ title: 'GCP docs: Data Access audit logs', url: 'https://cloud.google.com/logging/docs/audit/configure-data-access' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','au-3','au-12'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'Data Access logging is part of the broader logged-event-types KSI.' },
        { ksi_id: 'KSI-MLA-OSM', relationship: 'precedes', note: 'SIEM needs these logs as input.' },
      ],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'gcp',
    project_id: ctx.project,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-CNA-DFP — Defining Functionality and Privileges (GCP)
// =====================================================================
export async function collectCnaDfp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  const requiredConstraints = [
    'iam.disableServiceAccountKeyCreation',
    'iam.disableServiceAccountKeyUpload',
    'iam.automaticIamGrantsForDefaultServiceAccounts',
    'iam.allowedPolicyMemberDomains',
    'storage.uniformBucketLevelAccess',
    'storage.publicAccessPrevention',
    'compute.requireOsLogin',
    'compute.vmExternalIpAccess',
  ];
  const constraintStatus: Record<string, { enforced: boolean; reason?: string }> = {};
  try {
    const orgpolicy = await gcpAuth.googleClient<any>('orgpolicy', 'v2');
    for (const c2 of requiredConstraints) {
      try {
        const r = await orgpolicy.projects.policies.get({ name: `projects/${ctx.project}/policies/${c2}` });
        const enforced = (r.data.spec?.rules ?? []).some((rl: any) => rl.enforce === true || (rl.values?.allowedValues?.length > 0) || (rl.values?.deniedValues?.length > 0));
        constraintStatus[c2] = { enforced };
      } catch {
        constraintStatus[c2] = { enforced: false, reason: 'not set at project (may be inherited from org)' };
      }
    }
    evidence.push(ev('orgpolicy.required_constraints', constraintStatus));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'orgpolicy.projects.policies.get', 'orgpolicy.policy.get (roles/orgpolicy.policyViewer)')); }
  const unenforced = Object.entries(constraintStatus).filter(([_, v]) => !v.enforced).map(([k]) => k);

  let perimeterCount = 0;
  const perimeters: any[] = [];
  try {
    const acm = await gcpAuth.googleClient<any>('accesscontextmanager', 'v1');
    const policies = await acm.accessPolicies.list({});
    for (const ap of policies.data.accessPolicies ?? []) {
      const r = await acm.accessPolicies.servicePerimeters.list({ parent: ap.name, pageSize: 50 });
      perimeters.push(...(r.data.servicePerimeters ?? []));
    }
    perimeterCount = perimeters.length;
    evidence.push(ev('accesscontextmanager.servicePerimeters', perimeters.map((p) => ({ name: p.name, restrictedServices: p.status?.restrictedServices?.length }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'accesscontextmanager.accessPolicies.servicePerimeters.list', 'accesscontextmanager.servicePerimeters.list (roles/accesscontextmanager.policyReader)')); }

  let customRoleCount = 0;
  const customRolesWithWildcards: string[] = [];
  try {
    const iam = await gcpAuth.googleClient<any>('iam', 'v1');
    const r = await iam.projects.roles.list({ parent: `projects/${ctx.project}`, view: 'FULL' });
    const roles = r.data.roles ?? [];
    customRoleCount = roles.length;
    for (const role of roles) {
      const perms = role.includedPermissions ?? [];
      if (perms.some((p: string) => p.endsWith('.*'))) customRolesWithWildcards.push(role.name);
    }
    evidence.push(ev('iam.projects.roles.list', { count: customRoleCount, with_wildcards: customRolesWithWildcards }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'iam.projects.roles.list', 'iam.roles.list (roles/iam.roleViewer)')); }

  const findings = [
    finding({
      rule: 'gcp.org.required_constraints_enforced',
      passed: unenforced.length === 0,
      severity: 'high',
      current: {
        summary: unenforced.length === 0
          ? `All ${requiredConstraints.length} required org policy constraints are enforced.`
          : `${unenforced.length} of ${requiredConstraints.length} required constraints are NOT enforced.`,
        observations: { constraint_status: constraintStatus, unenforced },
      },
      target: { summary: `These constraints enforced at org or project: ${requiredConstraints.join(', ')}.`, rationale: 'NIST CM-7. Org policies are GCP-wide guardrails.' },
      gap: unenforced.length === 0 ? undefined : {
        description: 'Unenforced constraints let admins introduce anti-patterns.',
        affected_resources: unenforced.map((c2): AffectedResource => ({
          type: 'google_org_policy_policy', identifier: `projects/${ctx.project}/policies/${c2}`, name: c2, attributes: {},
        })),
      },
      remediation: unenforced.length === 0 ? undefined : {
        summary: 'Enforce each constraint at the org level via Terraform.',
        options: [{
          approach: 'Apply org policy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Each constraint can break existing behavior — audit + stage.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Audit + staged rollout.' },
          steps: ['Audit current usage per constraint.', 'Enforce at org or project.', 'Document any exceptions.'],
          example_code: 'resource "google_org_policy_policy" "uniform_bucket_access" {\n  name   = "organizations/${var.org_id}/policies/storage.uniformBucketLevelAccess"\n  parent = "organizations/${var.org_id}"\n  spec { rules { enforce = "TRUE" } }\n}',
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','cm-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'disableServiceAccountKeyCreation overlaps with AAM.' },
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'publicAccessPrevention + vmExternalIpAccess overlap with MAT.' },
      ],
    }),

    finding({
      rule: 'gcp.vpc_sc.prod_in_perimeter',
      passed: perimeterCount >= 1,
      severity: 'medium',
      current: {
        summary: perimeterCount >= 1
          ? `${perimeterCount} VPC SC perimeter(s) configured.`
          : 'No VPC SC perimeters.',
        observations: { perimeters: perimeters.map((p) => ({ name: p.name })) },
      },
      target: { summary: 'Prod project is inside at least one VPC SC perimeter restricting sensitive API access.', rationale: 'NIST AC-4. VPC SC is GCP\'s data-exfiltration boundary.' },
      gap: perimeterCount >= 1 ? undefined : {
        description: 'No perimeter; data-exfil possible.',
        affected_resources: [{ type: 'google_access_context_manager_service_perimeter', identifier: 'none', attributes: {} }],
      },
      remediation: perimeterCount >= 1 ? undefined : {
        summary: 'Create a perimeter around prod restricting storage/bigquery/kms APIs.',
        options: [{
          approach: 'Create perimeter via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'high', notes: 'Mis-scoped perimeter breaks cross-project traffic. Use dry-run.' },
          customer_visible: { level: 'low', notes: 'Affects cross-project sharing.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Design + dry-run + tuning.' },
          steps: ['Create access policy.', 'Define perimeter.', 'Dry-run 2-4 weeks.', 'Enforce.'],
          references: [{ title: 'VPC Service Controls', url: 'https://cloud.google.com/vpc-service-controls/docs/overview' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-4','sc-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-ULN', relationship: 'shares-remediation', note: 'VPC SC is part of logical networking.' },
      ],
    }),

    finding({
      rule: 'gcp.iam.custom_roles_no_wildcards',
      passed: customRolesWithWildcards.length === 0,
      severity: 'medium',
      current: {
        summary: customRolesWithWildcards.length === 0
          ? `All ${customRoleCount} custom IAM role(s) avoid wildcards.`
          : `${customRolesWithWildcards.length} custom role(s) have wildcard permissions.`,
        observations: { custom_role_count: customRoleCount, with_wildcards: customRolesWithWildcards },
      },
      target: { summary: 'Custom IAM roles enumerate specific permissions, no .* wildcards.', rationale: 'NIST AC-6. Wildcard custom roles drift into admin-equivalent.' },
      gap: customRolesWithWildcards.length === 0 ? undefined : {
        description: 'Wildcard permissions grant broader access than role name implies.',
        affected_resources: customRolesWithWildcards.map((n: string): AffectedResource => ({
          type: 'google_project_iam_custom_role', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: customRolesWithWildcards.length === 0 ? undefined : {
        summary: 'Replace .* with specific permissions actually used.',
        options: [{
          approach: 'Edit each custom role via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Tightening can break consumers; use Policy Analyzer.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per role.' },
          steps: ['Run Policy Analyzer.', 'Update role.', 'Apply Terraform.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}
