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

// =====================================================================
// KSI-IAM-ELP — Ensuring Least Privilege
// =====================================================================
/**
 * FedRAMP-aligned threshold for total Global Administrators. Microsoft's own
 * guidance is "no fewer than 2, no more than 5" so emergency access is preserved
 * while concentration of risk is limited. We pass when ≤ MAX.
 */
const GLOBAL_ADMIN_MAX = 5;
const GLOBAL_ADMIN_ROLE_TEMPLATE = '62e90394-69f5-4237-9190-012177145e10';

interface DirectoryRole { id?: string; displayName?: string; roleTemplateId?: string }
interface RoleAssignment { id?: string; principalId?: string; roleDefinitionId?: string; directoryScopeId?: string }
interface RoleEligibilitySchedule { id?: string; principalId?: string; roleDefinitionId?: string; status?: string; scheduleInfo?: any }

export async function collectIamElp(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Global Administrator membership count.
  const roles = await graphFetchAll<DirectoryRole>('/directoryRoles');
  warnings.push(...roles.warnings);
  const globalAdminRole = roles.items.find((r) => r.roleTemplateId === GLOBAL_ADMIN_ROLE_TEMPLATE);
  let memberCount = 0;
  if (globalAdminRole?.id) {
    const members = await graphFetchAll<{ id?: string; '@odata.type'?: string }>(`/directoryRoles/${globalAdminRole.id}/members`);
    warnings.push(...members.warnings);
    memberCount = members.items.length;
    evidence.push(ev('graph.globalAdmins', { role_id: globalAdminRole.id, member_count: memberCount, sample: members.items.slice(0, 10).map((m) => m.id) }));
  } else {
    // Role isn't activated until a member is assigned to it; emit a warning but
    // still produce the finding (passing — zero members means concentration risk
    // is theoretically minimised, but we surface this so the human reviewer
    // notices the emergency-access gap).
    evidence.push(ev('graph.globalAdmins', { role_id: null, member_count: 0, note: 'Global Administrator role not activated (no members assigned).' }));
    warnings.push('No members in the Global Administrator directory role — verify that at least 2 break-glass accounts exist for emergency access.');
  }

  findings.push(finding({
    rule: 'aad.global_admin_count_within_threshold', passed: memberCount <= GLOBAL_ADMIN_MAX, severity: 'high',
    current: {
      summary: `${memberCount} Global Administrator(s) — FedRAMP threshold is ≤ ${GLOBAL_ADMIN_MAX}.`,
      observations: { count: memberCount, threshold: GLOBAL_ADMIN_MAX },
    },
    target: {
      summary: `Total Global Administrators is ≥ 2 (emergency access) and ≤ ${GLOBAL_ADMIN_MAX} (least privilege).`,
      rationale: 'NIST AC-6, AC-6(5). Microsoft Entra ID guidance: limit Global Admin count to reduce concentration of risk; keep ≥ 2 for emergency-access continuity.',
    },
    gap: { description: `Too many principals hold the Global Administrator role (${memberCount} > ${GLOBAL_ADMIN_MAX}).`, affected_resources: [{ type: 'azure_aad_directory_role', identifier: 'Global Administrator', attributes: { count: memberCount } }] },
    remediation: {
      summary: 'Audit Global Admin assignments; demote principals to narrower built-in roles (User Administrator, Helpdesk Administrator, etc.) or convert to PIM-eligible assignments so the role is only active when needed.',
      options: [
        { approach: 'Convert standing Global Admin assignments to PIM-eligible (Entra ID P2).', mechanism: 'console', steps: ['Entra ID → Privileged Identity Management → Roles → Global Administrator', 'Select active assignment → Make eligible', 'Configure an activation policy requiring MFA + justification'] },
        { approach: 'Remove redundant grants.', mechanism: 'cli', steps: ['az ad directory-role member remove --role-id <gid> --member-id <uid>', 'or via Microsoft.Graph PowerShell: Remove-MgDirectoryRoleMember'] },
      ],
    },
    nist_controls: ['ac-6', 'ac-6.5', 'ac-6.7'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-JIT', relationship: 'shares-remediation', note: 'PIM eligible assignments back the JIT KSI.' }],
  }));

  // 2) PIM eligible assignments exist for admin roles (P2 feature).
  const elig = await graphFetchAll<RoleEligibilitySchedule>('/roleManagement/directory/roleEligibilitySchedules');
  warnings.push(...elig.warnings);
  const adminRoleDefIds = new Set([
    GLOBAL_ADMIN_ROLE_TEMPLATE,
    'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', // Application Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
  ]);
  const adminEligible = elig.items.filter((e) => e.roleDefinitionId && adminRoleDefIds.has(e.roleDefinitionId));
  evidence.push(ev('graph.pimEligibleAdminAssignments', { total_eligible: elig.items.length, admin_eligible: adminEligible.length }));
  findings.push(finding({
    rule: 'aad.pim_eligible_for_admin_roles', passed: adminEligible.length > 0, severity: 'medium',
    current: {
      summary: adminEligible.length > 0
        ? `${adminEligible.length} PIM-eligible assignment(s) cover privileged directory roles.`
        : 'No PIM-eligible assignments for privileged directory roles (or PIM is unavailable on this tenant).',
      observations: { admin_eligible: adminEligible.length, total_eligible: elig.items.length },
    },
    target: {
      summary: 'Privileged directory roles (Global Admin / Privileged Role Admin / etc.) are assigned via PIM (eligible activation) rather than as standing/permanent.',
      rationale: 'NIST AC-2(7), AC-6(2). Time-bound activation reduces persistent attack surface for admin accounts.',
    },
    gap: { description: 'No privileged role assignments use PIM eligibility — admin access is standing rather than just-in-time.', affected_resources: [{ type: 'azure_aad_pim_eligibility', identifier: 'admin-roles', attributes: {} }] },
    remediation: {
      summary: 'Adopt Microsoft Entra ID Privileged Identity Management (P2) and convert active admin assignments to eligible.',
      options: [
        { approach: 'Convert standing → eligible via PIM (P2 license required).', mechanism: 'console', steps: ['Entra ID → PIM → Azure AD roles → Roles', 'For each admin role: Add assignments → Eligible', 'Remove the matching standing/active assignment'] },
      ],
    },
    nist_controls: ['ac-2.7', 'ac-6.2'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-IAM-AAM — Automating Account Management
// =====================================================================
/** Dormancy threshold in days — accounts with no successful sign-in in this window are flagged. */
const DORMANT_DAYS = 90;
/** Severe-dormancy threshold (days); failing this is far more serious. */
const DORMANT_SEVERE_DAYS = 365;

interface AadUser {
  id?: string;
  userPrincipalName?: string;
  accountEnabled?: boolean;
  signInActivity?: { lastSignInDateTime?: string | null; lastNonInteractiveSignInDateTime?: string | null };
  createdDateTime?: string;
  userType?: string;
}

function daysSince(iso: string | null | undefined, now = Date.now()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now - t) / 86_400_000);
}

export async function collectIamAam(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // /users with signInActivity requires AuditLog.Read.All; if forbidden, the field
  // is silently omitted by Graph and our dormancy logic flags every user as
  // "never signed in" (lastSignInDateTime null). Surface that as a warning rather
  // than a false-positive.
  const users = await graphFetchAll<AadUser>(
    '/users?$select=id,userPrincipalName,accountEnabled,signInActivity,createdDateTime,userType',
  );
  warnings.push(...users.warnings);

  const enabledMembers = users.items.filter((u) => u.accountEnabled !== false && u.userType !== 'Guest');
  const total = enabledMembers.length;
  const dormant = enabledMembers.filter((u) => {
    const d = daysSince(u.signInActivity?.lastSignInDateTime);
    return d != null && d > DORMANT_DAYS;
  });
  const severelyDormant = enabledMembers.filter((u) => {
    const d = daysSince(u.signInActivity?.lastSignInDateTime);
    return d != null && d > DORMANT_SEVERE_DAYS;
  });
  const neverSignedIn = enabledMembers.filter((u) => u.signInActivity == null || u.signInActivity.lastSignInDateTime == null);

  // If *every* user lacks signInActivity it's almost certainly a permissions
  // issue (AuditLog.Read.All missing) — degrade gracefully.
  const allMissing = enabledMembers.length > 0 && neverSignedIn.length === enabledMembers.length;
  if (allMissing) {
    warnings.push('signInActivity field is missing on every user — the runner principal probably lacks the AuditLog.Read.All Microsoft Graph permission. Dormancy findings have been emitted in "data-missing" mode.');
  }

  evidence.push(ev('graph.users', {
    total_member_users: total,
    enabled_count: total,
    dormant_90d: dormant.length,
    severely_dormant_365d: severelyDormant.length,
    never_signed_in: neverSignedIn.length,
    auditlog_read_present: !allMissing,
    sample_dormant: dormant.slice(0, 20).map((u) => ({ id: u.id, upn: u.userPrincipalName, lastSignIn: u.signInActivity?.lastSignInDateTime ?? null })),
  }));

  // ── Finding 1: enabled accounts dormant > 90 days ──
  // Pass only when we actually have signInActivity data AND no dormant accounts.
  findings.push(finding({
    rule: 'aad.no_dormant_enabled_accounts', passed: !allMissing && dormant.length === 0, severity: 'medium',
    current: {
      summary: allMissing
        ? `Unable to verify dormancy — signInActivity field unavailable on all ${total} enabled user(s).`
        : `${dormant.length}/${total} enabled member account(s) have no interactive sign-in in the last ${DORMANT_DAYS} day(s).`,
      observations: { total, dormant_90d: dormant.length, severely_dormant: severelyDormant.length, never_signed_in: neverSignedIn.length, auditlog_permission_missing: allMissing },
    },
    target: { summary: `Enabled member accounts have an interactive sign-in within the last ${DORMANT_DAYS} days; dormant accounts are disabled or removed automatically.`, rationale: 'NIST AC-2(3), AC-2(13). Disable/delete inactive accounts on a defined schedule.' },
    gap: { description: 'Dormant accounts remain enabled, expanding the credential-theft attack surface.', affected_resources: dormant.slice(0, 50).map((u) => ({ type: 'azure_aad_user', identifier: u.userPrincipalName ?? (u.id ?? 'unknown'), attributes: { lastSignIn: u.signInActivity?.lastSignInDateTime ?? null } })) },
    remediation: {
      summary: 'Automate disable + later delete of dormant accounts via an Access Review (Entra ID P2) or a scheduled HR-driven provisioning flow.',
      options: [
        { approach: 'Access Review on all members (Entra ID P2).', mechanism: 'console', steps: ['Entra ID → Identity Governance → Access reviews → New', 'Scope: all members', 'Recurrence: quarterly; auto-apply results: disable on no-response'] },
        { approach: 'HR-driven SCIM provisioning.', mechanism: 'process', steps: ['Wire HR system → Entra ID via SCIM 2.0', 'Disable on termination event', 'Delete after 30-day retention'] },
      ],
    },
    nist_controls: ['ac-2', 'ac-2.3', 'ac-2.13'],
  }));

  // ── Finding 2: enabled accounts dormant > 365 days (severe / critical) ──
  findings.push(finding({
    rule: 'aad.no_severely_dormant_accounts', passed: !allMissing && severelyDormant.length === 0, severity: 'critical',
    current: {
      summary: allMissing
        ? `Unable to verify severe dormancy — signInActivity field unavailable.`
        : `${severelyDormant.length} enabled account(s) have not signed in for > ${DORMANT_SEVERE_DAYS} days.`,
      observations: { severely_dormant: severelyDormant.length, threshold_days: DORMANT_SEVERE_DAYS },
    },
    target: { summary: 'No enabled member account has been dormant for more than one year — these are removed (or at least disabled) automatically.', rationale: 'NIST AC-2(3), AC-2(13).' },
    gap: { description: `Enabled accounts dormant > ${DORMANT_SEVERE_DAYS} days remain in the tenant.`, affected_resources: severelyDormant.slice(0, 50).map((u) => ({ type: 'azure_aad_user', identifier: u.userPrincipalName ?? (u.id ?? 'unknown'), attributes: { lastSignIn: u.signInActivity?.lastSignInDateTime ?? null } })) },
    remediation: { summary: 'Disable + remove these accounts immediately, then bake the policy into Access Reviews so they cannot accumulate again.', options: [{ approach: 'Bulk-disable in PowerShell.', mechanism: 'cli', steps: ['Update-MgUser -UserId <upn> -AccountEnabled $false', 'After 30-day retention, Remove-MgUser -UserId <upn>'] }] },
    nist_controls: ['ac-2', 'ac-2.3'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
