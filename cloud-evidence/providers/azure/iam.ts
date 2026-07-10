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
    gap: { description: 'Dormant accounts remain enabled, expanding the credential-theft attack surface.', affected_resources: dormant.length ? dormant.slice(0, 50).map((u) => ({ type: 'azure_aad_user', identifier: u.userPrincipalName ?? (u.id ?? 'unknown'), attributes: { lastSignIn: u.signInActivity?.lastSignInDateTime ?? null } })) : [{ type: 'azure_aad_tenant', identifier: 'directory', name: 'signInActivity unreadable — dormancy indeterminate (missing AuditLog.Read.All)', attributes: { auditlog_permission_missing: allMissing } }] },
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
    gap: { description: `Enabled accounts dormant > ${DORMANT_SEVERE_DAYS} days remain in the tenant.`, affected_resources: severelyDormant.length ? severelyDormant.slice(0, 50).map((u) => ({ type: 'azure_aad_user', identifier: u.userPrincipalName ?? (u.id ?? 'unknown'), attributes: { lastSignIn: u.signInActivity?.lastSignInDateTime ?? null } })) : [{ type: 'azure_aad_tenant', identifier: 'directory', name: 'signInActivity unreadable — severe dormancy indeterminate (missing AuditLog.Read.All)', attributes: { auditlog_permission_missing: allMissing } }] },
    remediation: { summary: 'Disable + remove these accounts immediately, then bake the policy into Access Reviews so they cannot accumulate again.', options: [{ approach: 'Bulk-disable in PowerShell.', mechanism: 'cli', steps: ['Update-MgUser -UserId <upn> -AccountEnabled $false', 'After 30-day retention, Remove-MgUser -UserId <upn>'] }] },
    nist_controls: ['ac-2', 'ac-2.3'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-IAM-APM — Adopting Passwordless Methods
// =====================================================================
/**
 * "Adopting Passwordless Methods" maps cleanly to Microsoft Entra ID's
 * `authenticationStrength` references in Conditional Access. A CA policy that
 * grants only when the user satisfies a phishing-resistant strength (FIDO2,
 * Windows Hello for Business, certificate-based auth) is what FedRAMP wants.
 *
 * We look for any enabled CA policy whose `grantControls.authenticationStrength`
 * is non-null — and a stricter variant for admin roles specifically.
 */
export async function collectIamApm(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const ca = await graphFetchAll<CaPolicy>('/identity/conditionalAccess/policies', { maxPages: 20 });
  warnings.push(...ca.warnings);

  const enabledStrengthPolicies = ca.items.filter((p) => p.state === 'enabled' && !!p.grantControls?.authenticationStrength?.id);
  const adminStrengthPolicies = enabledStrengthPolicies.filter(targetsAdminRoles);
  evidence.push(ev('graph.conditionalAccess.authenticationStrength', {
    enabled_with_strength: enabledStrengthPolicies.length,
    admin_strength: adminStrengthPolicies.length,
    sample: enabledStrengthPolicies.slice(0, 10).map((p) => ({ id: p.id, displayName: p.displayName, strengthId: p.grantControls?.authenticationStrength?.id })),
  }));

  // ── Finding 1: at least one enabled CA policy uses authenticationStrength ──
  findings.push(finding({
    rule: 'aad.ca_uses_authentication_strength', passed: enabledStrengthPolicies.length > 0, severity: 'medium',
    current: {
      summary: enabledStrengthPolicies.length > 0
        ? `${enabledStrengthPolicies.length} enabled Conditional Access policy(ies) require a passwordless / phishing-resistant authentication strength.`
        : 'No enabled Conditional Access policy uses authenticationStrength — all sign-ins fall back to the default password-or-MFA path.',
      observations: { enabled_with_strength: enabledStrengthPolicies.length },
    },
    target: {
      summary: 'At least one enabled Conditional Access policy uses `grantControls.authenticationStrength` (FIDO2 / Windows Hello for Business / certificate-based) instead of the legacy "require MFA" built-in control.',
      rationale: 'NIST IA-2(11), IA-5(1)(c). FedRAMP guidance is to prefer phishing-resistant methods (PIV, FIDO2) for interactive sign-in.',
    },
    gap: { description: 'Authentication strength (the passwordless / phishing-resistant policy track) is not in use.', affected_resources: [{ type: 'azure_aad_ca_policy', identifier: 'none-using-strength', attributes: {} }] },
    remediation: {
      summary: 'Create a Conditional Access policy whose grant requires a built-in phishing-resistant strength (e.g. "Phishing-resistant MFA").',
      options: [
        { approach: 'Terraform azuread_conditional_access_policy.', mechanism: 'terraform', steps: ['grant_controls.authentication_strength_policy_id = <id of Phishing-resistant MFA built-in strength>', 'state = "enabled"', 'Roll out via a "report-only" stage first to find user-impact gaps'] },
      ],
    },
    nist_controls: ['ia-2.11', 'ia-5.1'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'authenticationStrength references also satisfy the IAM-MFA admin-MFA finding.' }],
  }));

  // ── Finding 2: admin roles get the strong policy ──
  findings.push(finding({
    rule: 'aad.ca_authentication_strength_for_admins', passed: adminStrengthPolicies.length > 0, severity: 'high',
    current: {
      summary: adminStrengthPolicies.length > 0
        ? `${adminStrengthPolicies.length} Conditional Access policy(ies) require an authenticationStrength on a privileged directory-role principal.`
        : 'No Conditional Access policy enforces an authenticationStrength on privileged directory roles — admins can still sign in with weak factors.',
      observations: { admin_strength: adminStrengthPolicies.length },
    },
    target: { summary: 'Privileged-role principals are required to satisfy a phishing-resistant authenticationStrength.', rationale: 'NIST IA-2(11), AC-6, AC-6(5).' },
    gap: { description: 'Admins can satisfy CA grants without a phishing-resistant method.', affected_resources: [{ type: 'azure_aad_ca_policy', identifier: 'no-admin-strength', attributes: {} }] },
    remediation: { summary: 'Target privileged directory-role templates in `conditions.users.includeRoles` and set `grantControls.authenticationStrength`.', options: [{ approach: 'Terraform.', mechanism: 'terraform', steps: ['conditions.users.included_roles = [<admin templates>]', 'grant_controls.authentication_strength_policy_id = <phishing-resistant id>', 'state = "enabled"'] }] },
    nist_controls: ['ia-2.11', 'ac-6', 'ac-6.5'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-IAM-SNU — Securing Non-User Authentication
// =====================================================================
/**
 * Maps to service-principal credential hygiene in Entra ID. Apps and SPs carry
 * `passwordCredentials` (client secrets) and `keyCredentials` (certs); each has
 * an `endDateTime`. We flag any credential that's already expired but still
 * present (cleanup hygiene) and any credential older than 365 days (rotation).
 */
const SP_CRED_ROTATION_DAYS = 365;

interface PasswordCredential { keyId?: string; endDateTime?: string; startDateTime?: string; displayName?: string }
interface KeyCredential { keyId?: string; endDateTime?: string; startDateTime?: string; usage?: string; type?: string }
interface AppOrSp {
  id?: string;
  appId?: string;
  displayName?: string;
  accountEnabled?: boolean;
  passwordCredentials?: PasswordCredential[];
  keyCredentials?: KeyCredential[];
}

export async function collectIamSnu(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Both /applications and /servicePrincipals — apps own the secrets/certs;
  // SPs are tenant-scoped instances. Either yields valid credential data.
  const apps = await graphFetchAll<AppOrSp>(
    '/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials',
    { maxPages: 50 },
  );
  warnings.push(...apps.warnings);

  const now = Date.now();
  const expired: Array<{ owner: string; ownerId?: string; kind: 'secret' | 'cert'; endDateTime: string | undefined }> = [];
  const stale: Array<{ owner: string; ownerId?: string; kind: 'secret' | 'cert'; ageDays: number }> = [];

  for (const a of apps.items) {
    const ownerLabel = a.displayName ?? a.appId ?? a.id ?? 'unknown';
    for (const pc of a.passwordCredentials ?? []) {
      const end = pc.endDateTime ? Date.parse(pc.endDateTime) : NaN;
      if (Number.isFinite(end) && end < now) expired.push({ owner: ownerLabel, ownerId: a.id, kind: 'secret', endDateTime: pc.endDateTime });
      const start = pc.startDateTime ? Date.parse(pc.startDateTime) : NaN;
      if (Number.isFinite(start)) {
        const ageDays = Math.floor((now - start) / 86_400_000);
        if (ageDays > SP_CRED_ROTATION_DAYS) stale.push({ owner: ownerLabel, ownerId: a.id, kind: 'secret', ageDays });
      }
    }
    for (const kc of a.keyCredentials ?? []) {
      const end = kc.endDateTime ? Date.parse(kc.endDateTime) : NaN;
      if (Number.isFinite(end) && end < now) expired.push({ owner: ownerLabel, ownerId: a.id, kind: 'cert', endDateTime: kc.endDateTime });
      const start = kc.startDateTime ? Date.parse(kc.startDateTime) : NaN;
      if (Number.isFinite(start)) {
        const ageDays = Math.floor((now - start) / 86_400_000);
        if (ageDays > SP_CRED_ROTATION_DAYS) stale.push({ owner: ownerLabel, ownerId: a.id, kind: 'cert', ageDays });
      }
    }
  }
  evidence.push(ev('graph.applications.credentials', {
    apps_count: apps.items.length,
    expired_credentials: expired.length,
    stale_credentials: stale.length,
    sample_expired: expired.slice(0, 20),
    sample_stale: stale.slice(0, 20),
  }));

  // ── Finding 1: no expired credentials lying around on apps ──
  findings.push(finding({
    rule: 'aad.sp_no_expired_credentials', passed: expired.length === 0, severity: 'medium',
    current: {
      summary: expired.length === 0
        ? `All app/SP credentials are within their endDateTime across ${apps.items.length} app(s).`
        : `${expired.length} expired credential(s) are still attached to apps/SPs.`,
      observations: { expired_count: expired.length, sample: expired.slice(0, 50) },
    },
    target: { summary: 'No app or service-principal carries a credential past its `endDateTime`. Expired credentials are removed promptly.', rationale: 'NIST IA-5, IA-5(2). Hygiene + reduces audit-log noise.' },
    gap: { description: 'Apps/SPs have credentials past their expiry date.', affected_resources: expired.slice(0, 50).map((e) => ({ type: 'azure_aad_app_credential', identifier: `${e.owner}::${e.kind}`, attributes: { endDateTime: e.endDateTime } })) },
    remediation: { summary: 'Audit the listed apps; remove any credential whose endDateTime is in the past.', options: [{ approach: 'PowerShell removal.', mechanism: 'cli', steps: ['$app = Get-MgApplication -ApplicationId <id>', 'Remove-MgApplicationPassword -ApplicationId <id> -KeyId <keyId>'] }] },
    nist_controls: ['ia-5', 'ia-5.2'],
  }));

  // ── Finding 2: credentials rotated within the SP_CRED_ROTATION_DAYS window ──
  findings.push(finding({
    rule: 'aad.sp_credentials_rotated_within_year', passed: stale.length === 0, severity: 'medium',
    current: {
      summary: stale.length === 0
        ? `No active app/SP credential exceeds the ${SP_CRED_ROTATION_DAYS}-day rotation window.`
        : `${stale.length} app/SP credential(s) exceed the ${SP_CRED_ROTATION_DAYS}-day rotation window.`,
      observations: { stale_count: stale.length, sample: stale.slice(0, 50) },
    },
    target: { summary: `App / service-principal credentials are rotated at least every ${SP_CRED_ROTATION_DAYS} days. Workload-identity federation (no secret) is preferred where possible.`, rationale: 'NIST IA-5(1), IA-5(13).' },
    gap: { description: 'App/SP credentials are older than the rotation threshold.', affected_resources: stale.slice(0, 50).map((s) => ({ type: 'azure_aad_app_credential', identifier: `${s.owner}::${s.kind}`, attributes: { ageDays: s.ageDays } })) },
    remediation: { summary: 'Rotate the listed credentials; migrate high-traffic SPs to federated workload identity to eliminate secrets entirely.', options: [{ approach: 'Workload identity federation (no secret).', mechanism: 'console', steps: ['Entra ID → App registrations → <app> → Certificates & secrets → Federated credentials', 'Bind to GitHub OIDC / AKS / GitHub OIDC / etc.'] }] },
    nist_controls: ['ia-5.1', 'ia-5.13'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-IAM-JIT — Authorizing Just-in-Time
// =====================================================================
/**
 * The PIM-eligibility *configuration* finding lives on KSI-IAM-ELP. JIT proves
 * the model is also *in use* — recent PIM activation requests on an admin role
 * are the strongest live signal that JIT is real, not just configured.
 */
const JIT_ACTIVATION_WINDOW_DAYS = 30;

interface RoleAssignmentScheduleRequest {
  id?: string;
  action?: string;
  status?: string;
  roleDefinitionId?: string;
  principalId?: string;
  createdDateTime?: string;
  scheduleInfo?: { startDateTime?: string };
}

export async function collectIamJit(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const reqs = await graphFetchAll<RoleAssignmentScheduleRequest>(
    '/roleManagement/directory/roleAssignmentScheduleRequests',
    { maxPages: 10 },
  );
  warnings.push(...reqs.warnings);

  const cutoff = Date.now() - JIT_ACTIVATION_WINDOW_DAYS * 86_400_000;
  const adminRoleDefs = new Set([
    GLOBAL_ADMIN_ROLE_TEMPLATE,
    'e8611ab8-c189-46e8-94e1-60213ab1f814',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
    '194ae4cb-b126-40b2-bd5b-6091b380977d',
    'fe930be7-5e62-47db-91af-98c3a49a38b1',
  ]);
  const recentAdminActivations = reqs.items.filter((r) => {
    if (r.action !== 'selfActivate' && r.action !== 'adminAssign') return false;
    if (r.status && !/granted|provisioned/i.test(r.status)) return false;
    if (!r.roleDefinitionId || !adminRoleDefs.has(r.roleDefinitionId)) return false;
    const t = Date.parse(r.createdDateTime ?? r.scheduleInfo?.startDateTime ?? '');
    return Number.isFinite(t) && t >= cutoff;
  });
  evidence.push(ev('graph.pimActivations', {
    total_requests: reqs.items.length,
    recent_admin_activations_30d: recentAdminActivations.length,
    sample: recentAdminActivations.slice(0, 10).map((r) => ({ id: r.id, action: r.action, role: r.roleDefinitionId, when: r.createdDateTime })),
  }));

  findings.push(finding({
    rule: 'aad.pim_admin_activation_within_30d', passed: recentAdminActivations.length > 0, severity: 'medium',
    current: {
      summary: recentAdminActivations.length > 0
        ? `${recentAdminActivations.length} PIM activation(s) on privileged directory roles in the last ${JIT_ACTIVATION_WINDOW_DAYS} day(s).`
        : `No PIM activations on privileged directory roles in the last ${JIT_ACTIVATION_WINDOW_DAYS} day(s) — JIT may be configured but unused (admins still rely on standing assignments).`,
      observations: { recent_admin_activations_30d: recentAdminActivations.length },
    },
    target: {
      summary: 'Privileged operations are performed via PIM activations (just-in-time), not via standing role assignments — at least one activation is observable in the recent window.',
      rationale: 'NIST AC-2(7), AC-6(2). JIT activation evidence proves the JIT model is operationally live, not just configured.',
    },
    gap: { description: `No PIM activations on admin roles in the last ${JIT_ACTIVATION_WINDOW_DAYS} days.`, affected_resources: [{ type: 'azure_aad_pim_activation', identifier: 'admin-roles', attributes: {} }] },
    remediation: {
      summary: 'Confirm PIM is configured for admin roles (IAM-ELP), then deprecate any remaining standing admin assignments and require activation for every privileged action.',
      options: [{ approach: 'Configure activation policies (P2).', mechanism: 'console', steps: ['Entra ID → PIM → Azure AD roles → Roles → Global Administrator → Role settings → Edit', 'Require MFA on activation = Yes', 'Require justification on activation = Yes', 'Maximum activation duration ≤ 4h'] }],
    },
    nist_controls: ['ac-2.7', 'ac-6.2'],
    cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-ELP', relationship: 'depends-on', note: 'PIM eligibility (ELP) is the configuration; JIT activations are the runtime evidence.' }],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}

// =====================================================================
// KSI-IAM-SUS — Responding to Suspicious Activity
// =====================================================================
/**
 * Entra ID Identity Protection lets Conditional Access policies condition on
 * `signInRiskLevels` and `userRiskLevels` (low / medium / high). A risk-based
 * CA policy is the FedRAMP-meaningful "auto-respond to suspicious activity"
 * signal — it can require password reset, MFA challenge, or block sign-in based
 * on the risk score.
 */
export async function collectIamSus(_ctx: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  const ca = await graphFetchAll<CaPolicy & { conditions?: { signInRiskLevels?: string[]; userRiskLevels?: string[] } }>(
    '/identity/conditionalAccess/policies',
    { maxPages: 20 },
  );
  warnings.push(...ca.warnings);

  const enabledRiskPolicies = ca.items.filter((p) => {
    if (p.state !== 'enabled') return false;
    const sig = ((p.conditions as any)?.signInRiskLevels ?? []) as string[];
    const usr = ((p.conditions as any)?.userRiskLevels ?? []) as string[];
    return sig.length > 0 || usr.length > 0;
  });
  evidence.push(ev('graph.conditionalAccess.riskBased', {
    enabled_risk_policies: enabledRiskPolicies.length,
    sample: enabledRiskPolicies.slice(0, 10).map((p) => ({
      id: p.id,
      displayName: p.displayName,
      signInRiskLevels: (p.conditions as any)?.signInRiskLevels ?? [],
      userRiskLevels: (p.conditions as any)?.userRiskLevels ?? [],
    })),
  }));

  findings.push(finding({
    rule: 'aad.risk_based_conditional_access', passed: enabledRiskPolicies.length > 0, severity: 'high',
    current: {
      summary: enabledRiskPolicies.length > 0
        ? `${enabledRiskPolicies.length} enabled Conditional Access policy(ies) react to sign-in or user risk signals (Identity Protection).`
        : 'No enabled Conditional Access policy reacts to Identity Protection risk signals — suspicious sign-ins do not trigger automated action.',
      observations: { risk_based_policies: enabledRiskPolicies.length },
    },
    target: {
      summary: 'At least one enabled Conditional Access policy uses `signInRiskLevels` or `userRiskLevels` to automatically require step-up MFA, password reset, or block sign-in on suspicious activity.',
      rationale: 'NIST AU-6, IR-4, SI-4(4), SI-4(7). FedRAMP requires automated response to suspicious activity on privileged accounts.',
    },
    gap: { description: 'Identity Protection risk signals exist but no Conditional Access policy reacts to them.', affected_resources: [{ type: 'azure_aad_identity_protection', identifier: 'risk-based-ca', attributes: {} }] },
    remediation: {
      summary: 'Create two Conditional Access policies in Identity Protection: (a) high sign-in risk → block, and (b) medium+ user risk → require password change (Entra ID P2 required).',
      options: [
        { approach: 'Terraform azuread_conditional_access_policy with risk levels.', mechanism: 'terraform', steps: ['conditions.sign_in_risk_levels = ["high"]', 'grant_controls.built_in_controls = ["block"]', 'state = "enabled"', 'Repeat for conditions.user_risk_levels = ["high"] → grant_controls.built_in_controls = ["passwordChange"]'] },
      ],
    },
    nist_controls: ['au-6', 'ir-4', 'si-4', 'si-4.4', 'si-4.7'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings };
}
