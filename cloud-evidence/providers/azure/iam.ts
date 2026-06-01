/**
 * Azure / Microsoft Entra ID IAM collectors (AZ-IAM-MFA).
 *
 * First Azure KSI collector — establishes the per-KSI Azure dispatch pattern
 * other Azure IAM/network/logging collectors will mirror. Uses Microsoft Graph
 * over plain REST (`core/auth/azure-graph.ts`) — no @microsoft/microsoft-graph
 * SDK dep — keeping the read-only contract intentional (the helper only exposes
 * GET).
 *
 * KSI-IAM-MFA — two findings:
 *   1. `aad.security_defaults_or_ca_mfa_for_all_users` — Security Defaults are
 *      enabled, OR a Conditional Access (CA) policy enforces MFA on **all users**.
 *   2. `aad.ca_mfa_for_admin_roles` — at least one enabled CA policy enforces
 *      MFA on admin directory roles (Global / Privileged Role / Application /
 *      Security Administrator etc.).
 *
 * Read-only via the Graph helper (GET only). Every Graph error is captured as a
 * warning so the collector never crashes the run.
 */
import type { ProviderBlock, RawEvidence, Finding } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';
import { graphFetchAll, graphFetchOne } from '../../core/auth/azure-graph.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

/**
 * Built-in directory-role *templateIds* whose membership confers privileged
 * tenant control. A CA policy that targets any of these via
 * `conditions.users.includeRoles` is enforcing MFA on admins.
 *
 * Source: Microsoft Entra ID built-in roles reference (these IDs are stable
 * across tenants; they're product constants, not per-tenant role-instance ids).
 */
const ADMIN_ROLE_TEMPLATE_IDS = new Set<string>([
  '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
  'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', // Application Administrator
  '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
  '729827e3-9c14-49f7-bb1b-9608f156bbb8', // Helpdesk Administrator
  'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
  '966707d0-3269-4727-9be2-8c3a10f19b9d', // Password Administrator
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
  '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
]);

interface CaPolicy {
  id?: string;
  displayName?: string;
  state?: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced' | string;
  conditions?: {
    users?: {
      includeUsers?: string[];
      excludeUsers?: string[];
      includeRoles?: string[];
      excludeRoles?: string[];
      includeGroups?: string[];
      excludeGroups?: string[];
    };
    applications?: {
      includeApplications?: string[];
    };
  };
  grantControls?: {
    operator?: string;
    builtInControls?: string[];
    customAuthenticationFactors?: string[];
    authenticationStrength?: { id?: string };
  };
}

/** A CA policy enforces MFA if it's enabled and lists `mfa` in builtInControls. */
function policyEnforcesMfa(p: CaPolicy): boolean {
  if (p.state !== 'enabled') return false;
  const controls = (p.grantControls?.builtInControls ?? []).map((c) => c.toLowerCase());
  if (controls.includes('mfa')) return true;
  // Authentication-strength references (newer model) also satisfy MFA when the
  // strength includes a phishing-resistant or strong method — we conservatively
  // treat any non-null authenticationStrength reference as MFA-equivalent.
  if (p.grantControls?.authenticationStrength?.id) return true;
  return false;
}

function targetsAllUsers(p: CaPolicy): boolean {
  const inc = (p.conditions?.users?.includeUsers ?? []).map((s) => s.toLowerCase());
  return inc.includes('all');
}

function targetsAdminRoles(p: CaPolicy): boolean {
  const inc = p.conditions?.users?.includeRoles ?? [];
  return inc.some((r) => ADMIN_ROLE_TEMPLATE_IDS.has(r));
}

// =====================================================================
// KSI-IAM-MFA — Multi-Factor Authentication
// =====================================================================
export async function collectIamMfa(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Security Defaults state.
  const sd = await graphFetchOne<{ isEnabled?: boolean; id?: string; displayName?: string }>(
    '/policies/identitySecurityDefaultsEnforcementPolicy',
  );
  warnings.push(...sd.warnings);
  const securityDefaultsEnabled = sd.data?.isEnabled === true;
  evidence.push(ev('graph.securityDefaults', { enabled: securityDefaultsEnabled, raw: sd.data }));

  // 2) Conditional Access policies.
  const ca = await graphFetchAll<CaPolicy>('/identity/conditionalAccess/policies', { maxPages: 20 });
  warnings.push(...ca.warnings);
  const enabledMfaPolicies = ca.items.filter(policyEnforcesMfa);
  const allUsersMfa = enabledMfaPolicies.filter(targetsAllUsers);
  const adminMfa = enabledMfaPolicies.filter(targetsAdminRoles);
  evidence.push(ev('graph.conditionalAccess.policies', {
    total: ca.items.length,
    enabled_mfa: enabledMfaPolicies.length,
    all_users_mfa: allUsersMfa.length,
    admin_role_mfa: adminMfa.length,
    sample: enabledMfaPolicies.slice(0, 10).map((p) => ({ id: p.id, displayName: p.displayName, state: p.state })),
  }));

  // ── Finding 1: Security Defaults OR all-users CA-MFA policy exists ──
  const f1Pass = securityDefaultsEnabled || allUsersMfa.length > 0;
  findings.push(finding({
    rule: 'aad.security_defaults_or_ca_mfa_for_all_users', passed: f1Pass, severity: 'high',
    current: {
      summary: securityDefaultsEnabled
        ? 'Microsoft Entra Security Defaults are enabled — MFA is enforced on all users.'
        : (allUsersMfa.length > 0
          ? `${allUsersMfa.length} enabled Conditional Access policy(ies) enforce MFA on all users.`
          : 'Neither Security Defaults nor an all-users MFA Conditional Access policy is enabled.'),
      observations: { securityDefaultsEnabled, allUsersMfaPolicies: allUsersMfa.length },
    },
    target: {
      summary: 'Security Defaults are enabled, OR an enabled Conditional Access policy enforces MFA on `includeUsers = All`.',
      rationale: 'NIST IA-2(1), IA-2(2). FedRAMP requires MFA on all interactive sign-ins.',
    },
    gap: { description: 'MFA is not universally enforced via Security Defaults or a tenant-wide Conditional Access policy.', affected_resources: [{ type: 'azure_aad_tenant', identifier: 'tenant', attributes: {} }] },
    remediation: {
      summary: 'Either turn on Security Defaults (Entra ID → Properties → Security Defaults), or create an enabled Conditional Access policy that includes All Users and grants MFA.',
      options: [
        { approach: 'Conditional Access (recommended for tenants with Entra ID P1/P2).', mechanism: 'terraform', steps: ['Create azuread_conditional_access_policy', 'conditions.users.included_users = ["All"]', 'grant_controls.built_in_controls = ["mfa"]', 'state = "enabled"'] },
        { approach: 'Security Defaults (free tier).', mechanism: 'console', steps: ['Entra admin center → Properties → Manage Security Defaults → Enable'] },
      ],
    },
    nist_controls: ['ia-2', 'ia-2.1', 'ia-2.2', 'ac-7'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-APM', relationship: 'shares-remediation', note: 'Authentication-strength policies feed the passwordless KSI.' }],
  }));

  // ── Finding 2: CA policy enforces MFA on admin directory roles ──
  findings.push(finding({
    rule: 'aad.ca_mfa_for_admin_roles', passed: adminMfa.length > 0, severity: 'critical',
    current: {
      summary: adminMfa.length > 0
        ? `${adminMfa.length} Conditional Access policy(ies) enforce MFA on at least one privileged directory role.`
        : 'No Conditional Access policy enforces MFA on privileged directory roles.',
      observations: { admin_role_policies: adminMfa.length, sample: adminMfa.slice(0, 10).map((p) => ({ id: p.id, displayName: p.displayName, includeRoles: p.conditions?.users?.includeRoles })) },
    },
    target: {
      summary: 'At least one enabled Conditional Access policy includes one or more admin directory roles (Global Admin, Privileged Role Admin, Application Admin, etc.) and grants MFA.',
      rationale: 'NIST IA-2(1), AC-6, AC-6(5). FedRAMP requires MFA for privileged accounts.',
    },
    gap: { description: 'Privileged-role accounts can sign in without an MFA challenge enforced by Conditional Access.', affected_resources: [{ type: 'azure_aad_directory_role', identifier: 'admin-roles', attributes: {} }] },
    remediation: {
      summary: 'Create an enabled Conditional Access policy targeting administrative directory-role templates with MFA in builtInControls.',
      options: [
        { approach: 'Terraform azuread_conditional_access_policy.', mechanism: 'terraform', steps: ['conditions.users.included_roles = [<Global Admin template id>, <Privileged Role Admin template id>, ...]', 'grant_controls.built_in_controls = ["mfa"]', 'state = "enabled"'] },
      ],
    },
    nist_controls: ['ia-2', 'ia-2.1', 'ac-6', 'ac-6.5'],
  }));

  // External-IdP alternative-satisfier signal: a non-Microsoft IdP could be
  // brokering MFA before tokens hit Entra (Okta, Ping, etc.). The CA + Security
  // Defaults checks above don't see that. We surface it as awareness so the
  // human reviewer can attach the upstream IdP attestation if applicable.
  const ksiLevelAlternatives = [
    {
      via: 'External SAML/OIDC IdP enforcing MFA upstream',
      description: 'An external IdP (Okta, Ping, ADFS, …) may enforce MFA before tokens reach Entra ID. The Conditional Access / Security Defaults views above cannot observe that.',
      evidence_required: ['Vendor attestation of MFA enforcement', 'Sample sign-in audit log showing MFA claim'],
      detected: false,
      detection_signals: [],
    },
  ];

  return {
    provider: 'azure',
    account_id: null,
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: ksiLevelAlternatives,
  };
}
