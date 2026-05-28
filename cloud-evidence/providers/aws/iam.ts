/**
 * AWS IAM evidence collectors.
 *
 * One exported function per IAM KSI. Each returns a ProviderBlock containing
 * raw SDK evidence + findings. Every SDK call is read-only and guarded by
 * the read-only wrapper in core/readonly-guardrail.ts.
 */
import {
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  GetAccountSummaryCommand,
  GetAccountPasswordPolicyCommand,
  ListPoliciesCommand,
  GetPolicyVersionCommand,
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
  GetServiceLastAccessedDetailsCommand,
  GenerateServiceLastAccessedDetailsCommand,
  ListVirtualMFADevicesCommand,
  ListAttachedUserPoliciesCommand,
  ListUserPoliciesCommand,
  GetUserCommand,
  GetLoginProfileCommand,
  ListAccountAliasesCommand,
  ListSAMLProvidersCommand,
  ListOpenIDConnectProvidersCommand,
} from '@aws-sdk/client-iam';
import {
  ListInstancesCommand,
  ListPermissionSetsCommand,
  DescribePermissionSetCommand,
  ListAccountAssignmentsCommand,
  DescribeInstanceAccessControlAttributeConfigurationCommand,
} from '@aws-sdk/client-sso-admin';
import {
  ListUsersCommand as IdsListUsersCommand,
  ListGroupsCommand as IdsListGroupsCommand,
} from '@aws-sdk/client-identitystore';
import {
  DescribeOrganizationCommand,
  ListAccountsCommand,
  ListPoliciesCommand as OrgListPoliciesCommand,
  DescribePolicyCommand as OrgDescribePolicyCommand,
} from '@aws-sdk/client-organizations';
import {
  ListAnalyzersCommand,
  ListFindingsCommand as AaListFindingsCommand,
} from '@aws-sdk/client-accessanalyzer';
import { ListDetectorsCommand, GetDetectorCommand, ListFindingsCommand as GdListFindingsCommand } from '@aws-sdk/client-guardduty';
import { GetFindingsCommand as ShGetFindingsCommand } from '@aws-sdk/client-securityhub';
import { ListRulesCommand, ListTargetsByRuleCommand } from '@aws-sdk/client-eventbridge';
import { DescribeSessionsCommand } from '@aws-sdk/client-ssm';
import { ListUserPoolsCommand, DescribeUserPoolCommand } from '@aws-sdk/client-cognito-identity-provider';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

const DEFAULT_REGION = 'us-east-1';

function nowIso(): string {
  return new Date().toISOString();
}

function ev(source: string, data: unknown): RawEvidence {
  // Schema requires `data` to be PRESENT (not just `any` typed). When the SDK
  // returns undefined for an optional field, we coerce to null so JSON
  // serialization keeps the key.
  return { source, captured_at: nowIso(), data: data === undefined ? null : data };
}

interface Ctx {
  region: string;
  auth: aws.AwsAuth;
  account: string | null;
}

async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? DEFAULT_REGION;
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account: string | null = c.aws?.account_id ?? null;
  if (!account) {
    try {
      const me = await aws.whoAmI(auth);
      account = me.account;
    } catch {
      account = null;
    }
  }
  return { region, auth, account };
}

// ---- Shared lookups ----

// Hard cap to prevent runaway pagination — at MaxItems=100, this allows
// 100 000 users/policies/etc. AWS account quotas are typically much lower.
// If you legitimately have more, raise this and audit the call site.
const MAX_PAGINATION_ITERATIONS = 1000;

async function listAllIamUsers(ctx: Ctx): Promise<Array<{ UserName?: string; CreateDate?: Date; PasswordLastUsed?: Date }>> {
  const client = aws.iam(ctx.auth);
  const users: Array<{ UserName?: string; CreateDate?: Date; PasswordLastUsed?: Date }> = [];
  let marker: string | undefined;
  let prevMarker: string | undefined;
  let iter = 0;
  do {
    const out = await client.send(new ListUsersCommand({ Marker: marker, MaxItems: 100 }));
    users.push(...(out.Users ?? []));
    prevMarker = marker;
    marker = out.IsTruncated ? out.Marker : undefined;
    // Defense: if AWS returns the same marker twice (broken pagination), bail.
    if (marker && marker === prevMarker) break;
    if (++iter >= MAX_PAGINATION_ITERATIONS) break;
  } while (marker);
  return users;
}

async function ageInDays(d: Date | undefined): Promise<number | null> {
  if (!d) return null;
  return Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
}

// =====================================================================
// KSI-IAM-AAM — Automating Account Management
// =====================================================================
export async function collectIamAam(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // ---- Credential report ----
  // GenerateCredentialReport kicks off a server-side report; GetCredentialReport
  // returns the CSV. Both are read operations under ReadOnlyAccess.
  let credentialReport: any[] = [];
  try {
    await iamClient.send(new GenerateCredentialReportCommand({}));
    const r = await iamClient.send(new GetCredentialReportCommand({}));
    const csv = Buffer.from(r.Content ?? new Uint8Array()).toString('utf8');
    credentialReport = parseCsv(csv);
    evidence.push(ev('iam.GetCredentialReport', { row_count: credentialReport.length }));
  } catch (e: any) {
    warnings.push(`GetCredentialReport: ${e.message}`);
  }

  // ---- IAM users (federation-bypass surface) ----
  const users = await listAllIamUsers(ctx);
  evidence.push(ev('iam.ListUsers', { count: users.length, sample: users.slice(0, 5).map((u) => u.UserName) }));

  // ---- Access key inventory ----
  const usersWithOldKeys: Array<{ user: string; keyId: string; ageDays: number }> = [];
  const usersWithPasswordNoMfa: string[] = [];
  for (const u of users) {
    if (!u.UserName) continue;
    // Split the two SDK calls so a permission failure names the exact action.
    try {
      const ak = await iamClient.send(new ListAccessKeysCommand({ UserName: u.UserName }));
      for (const md of ak.AccessKeyMetadata ?? []) {
        const days = await ageInDays(md.CreateDate);
        if (md.AccessKeyId && days != null && days > 90) {
          usersWithOldKeys.push({ user: u.UserName, keyId: md.AccessKeyId, ageDays: days });
        }
      }
    } catch (e: any) {
      warnings.push(diagnoseAwsError(e, `iam.ListAccessKeys ${u.UserName}`, 'iam:ListAccessKeys'));
    }
    try {
      const mfa = await iamClient.send(new ListMFADevicesCommand({ UserName: u.UserName }));
      const hasPassword = credentialReport.find((row) => row.user === u.UserName)?.password_enabled === 'true';
      if (hasPassword && (mfa.MFADevices ?? []).length === 0) {
        usersWithPasswordNoMfa.push(u.UserName);
      }
    } catch (e: any) {
      warnings.push(diagnoseAwsError(e, `iam.ListMFADevices ${u.UserName}`, 'iam:ListMFADevices'));
    }
  }
  evidence.push(ev('iam.access_keys_audit', { users_with_old_keys_gt_90d: usersWithOldKeys, users_with_password_no_mfa: usersWithPasswordNoMfa }));

  // ---- IAM Identity Center (SSO) ----
  let identityCenterInstances = 0;
  let permissionSets = 0;
  let accountAssignments = 0;
  let abacConfigured = false;
  let identityStoreUsers = 0;
  let identityStoreGroups = 0;
  try {
    const ssoa = aws.ssoadmin(ctx.auth);
    const insts = await ssoa.send(new ListInstancesCommand({}));
    identityCenterInstances = insts.Instances?.length ?? 0;
    evidence.push(ev('sso-admin.ListInstances', insts.Instances ?? []));

    for (const inst of insts.Instances ?? []) {
      if (!inst.InstanceArn || !inst.IdentityStoreId) continue;
      // Permission sets
      let psToken: string | undefined;
      let psIter = 0;
      do {
        const ps = await ssoa.send(new ListPermissionSetsCommand({ InstanceArn: inst.InstanceArn, NextToken: psToken }));
        permissionSets += ps.PermissionSets?.length ?? 0;
        const next = ps.NextToken;
        if (next && next === psToken) break;  // broken pagination guard
        psToken = next;
      } while (psToken && ++psIter < MAX_PAGINATION_ITERATIONS);

      // ABAC config
      try {
        const abac = await ssoa.send(new DescribeInstanceAccessControlAttributeConfigurationCommand({ InstanceArn: inst.InstanceArn }));
        abacConfigured = (abac.InstanceAccessControlAttributeConfiguration?.AccessControlAttributes?.length ?? 0) > 0;
        evidence.push(ev('sso-admin.DescribeInstanceAccessControlAttributeConfiguration', { abac_attribute_count: abac.InstanceAccessControlAttributeConfiguration?.AccessControlAttributes?.length ?? 0 }));
      } catch (e: any) {
        warnings.push(`DescribeInstanceAccessControlAttributeConfiguration: ${e.message}`);
      }

      // Identity Store users/groups
      try {
        const ids = aws.identitystore(ctx.auth);
        let utok: string | undefined;
        let uIter = 0;
        do {
          const u = await ids.send(new IdsListUsersCommand({ IdentityStoreId: inst.IdentityStoreId, NextToken: utok, MaxResults: 100 }));
          identityStoreUsers += u.Users?.length ?? 0;
          const next = u.NextToken;
          if (next && next === utok) break;
          utok = next;
        } while (utok && ++uIter < MAX_PAGINATION_ITERATIONS);
        let gtok: string | undefined;
        let gIter = 0;
        do {
          const g = await ids.send(new IdsListGroupsCommand({ IdentityStoreId: inst.IdentityStoreId, NextToken: gtok, MaxResults: 100 }));
          identityStoreGroups += g.Groups?.length ?? 0;
          const next = g.NextToken;
          if (next && next === gtok) break;
          gtok = next;
        } while (gtok && ++gIter < MAX_PAGINATION_ITERATIONS);
      } catch (e: any) {
        warnings.push(`identitystore listing: ${e.message}`);
      }
    }
  } catch (e: any) {
    warnings.push(`IAM Identity Center listing: ${e.message}`);
  }
  evidence.push(ev('identity_center.summary', { identityCenterInstances, permissionSets, accountAssignments, abacConfigured, identityStoreUsers, identityStoreGroups }));

  // ---- Access Analyzer unused-access findings ----
  let unusedAccessFindings = 0;
  try {
    const aa = aws.accessanalyzer(ctx.auth);
    const an = await aa.send(new ListAnalyzersCommand({ type: 'ACCOUNT_UNUSED_ACCESS' }));
    for (const analyzer of an.analyzers ?? []) {
      let tok: string | undefined;
      do {
        const f = await aa.send(new AaListFindingsCommand({ analyzerArn: analyzer.arn, nextToken: tok, maxResults: 100 }));
        unusedAccessFindings += f.findings?.length ?? 0;
        tok = f.nextToken;
      } while (tok);
    }
    evidence.push(ev('accessanalyzer.unused_access', { findings_count: unusedAccessFindings }));
  } catch (e: any) {
    warnings.push(`Access Analyzer unused: ${e.message}`);
  }

  // ---- Alternative satisfiers ----
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External IdP with SCIM provisioning (Okta, Azure AD, Google Workspace)',
      description: 'When SCIM provisions Identity Store, account lifecycle is automated upstream. Deactivation in the IdP propagates within minutes.',
      evidence_required: [
        'IdP SCIM provisioning settings export',
        'Sample SCIM provisioning log showing recent user lifecycle event',
        'List of groups mapped from IdP to permission sets',
      ],
      detected: identityCenterInstances >= 1 && identityStoreUsers >= 1,
      detection_signals: [
        `Identity Center instances: ${identityCenterInstances}`,
        `Identity Store users: ${identityStoreUsers}`,
        `Identity Store groups: ${identityStoreGroups}`,
      ],
    },
  ];

  // ---- Findings (rich schema) ----
  const findings = [
    finding({
      rule: 'aws.iam.federation_is_primary_access_path',
      passed: identityCenterInstances >= 1 && identityStoreUsers >= 1,
      severity: 'high',
      current: {
        summary: identityCenterInstances >= 1
          ? `IAM Identity Center is configured (${identityCenterInstances} instance) with ${permissionSets} permission set(s) and ${identityStoreUsers} federated user(s) across ${identityStoreGroups} group(s).`
          : 'IAM Identity Center is not configured. Access likely happens via standalone IAM users — lifecycle is manual.',
        observations: { identityCenterInstances, permissionSets, identityStoreUsers, identityStoreGroups, abacConfigured },
      },
      target: {
        summary: 'Identity Center (or equivalent federation) is the primary access path: ≥1 instance, ≥1 permission set, populated Identity Store.',
        rationale: 'NIST AC-2(2) and IA-12 require automated account management. Federation pushes account lifecycle to the IdP, so deprovisioning is one click and propagates within minutes.',
      },
      gap: (identityCenterInstances >= 1 && identityStoreUsers >= 1) ? undefined : {
        description: 'Without federation, account creation/modification/deactivation happens manually in IAM. This is slow, error-prone, and does not satisfy AC-2(2).',
        affected_resources: [{ type: 'aws_ssoadmin_instance', identifier: ctx.account ?? 'unknown', attributes: { identityCenterInstances } }],
      },
      remediation: (identityCenterInstances >= 1 && identityStoreUsers >= 1) ? undefined : {
        summary: 'Stand up IAM Identity Center, connect your IdP via SCIM, define permission sets, migrate users.',
        options: [{
          approach: 'Enable Identity Center + connect external IdP via SCIM.',
          mechanism: 'terraform',
          owner_team: 'Identity / IT',
          cost_impact: { level: 'low', notes: 'Identity Center is free; existing IdP (Okta, Azure AD) may have SSO-tier costs.' },
          availability_impact: { level: 'low', notes: 'Net-new — does not affect existing users until you start migrating them.' },
          customer_visible: { level: 'none', notes: 'Internal change.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Setup is days; full user migration is weeks if hundreds of users.' },
          steps: [
            'In AWS Organizations management account, enable Identity Center for the org.',
            'In your IdP, configure the AWS SSO app (Okta/Azure AD has built-in templates).',
            'Enable SCIM provisioning from IdP → Identity Store.',
            'Create permission sets matching your access tiers (Admin / Developer / ReadOnly).',
            'Assign permission sets to IdP groups + AWS accounts.',
            'Migrate users (cut over the IAM-MFA Finding 2 remediation in parallel).',
          ],
          example_code: `module "identity_center" {
  source = "aws-ia/identity-center/aws"
  permission_sets = {
    AdminAccess      = { managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"], session_duration = "PT1H" }
    DeveloperAccess  = { managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"], session_duration = "PT2H" }
    ReadOnlyAccess   = { managed_policy_arns = ["arn:aws:iam::aws:policy/ReadOnlyAccess"], session_duration = "PT4H" }
  }
}`,
          references: [
            { title: 'AWS docs: IAM Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html' },
            { title: 'AWS docs: SCIM with Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/scim-profile-saml.html' },
          ],
        }],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ac-2.2','ac-2.3','ia-12','ia-12.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Identity Center setup satisfies MFA enforcement at the same time.' },
        { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Permission set design IS least-privilege design.' },
      ],
    }),

    finding({
      rule: 'aws.iam.standalone_users_minimized',
      passed: users.length === 0,
      severity: 'high',
      current: {
        summary: `${users.length} standalone IAM user(s) exist. Federation should push this toward 0 (humans) + small N (legacy automation pending migration to roles).`,
        observations: { count: users.length, users: users.map((u) => ({ UserName: u.UserName, CreateDate: u.CreateDate, PasswordLastUsed: u.PasswordLastUsed })) },
      },
      target: {
        summary: 'Zero standalone IAM users for humans. Any remaining users are documented exceptions tagged with purpose.',
        rationale: 'Standalone IAM users are not lifecycle-managed by the IdP. NIST AC-2 calls for centralized account management.',
      },
      gap: users.length === 0 ? undefined : {
        description: 'Each standalone IAM user is a parallel lifecycle channel that the IdP cannot deactivate.',
        affected_resources: users.map<AffectedResource>((u) => ({
          type: 'aws_iam_user',
          identifier: `arn:aws:iam::${ctx.account}:user/${u.UserName}`,
          name: u.UserName,
          attributes: { CreateDate: u.CreateDate, PasswordLastUsed: u.PasswordLastUsed },
        })),
      },
      remediation: users.length === 0 ? undefined : {
        summary: 'For each user, decide: human (migrate to Identity Center) or workload (replace with IAM role).',
        options: [{
          approach: 'Triage IAM users and migrate or replace each one.',
          mechanism: 'process',
          owner_team: 'Identity / IT',
          cost_impact: { level: 'none', notes: 'No additional charges.' },
          availability_impact: { level: 'medium', notes: 'Coordinated migration; per-user / per-workload validation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Triage + migration + decommission.' },
          steps: [
            'For each IAM user, identify: is this a human or workload?',
            'Humans → see KSI-IAM-MFA Finding 2 remediation (migrate to Identity Center).',
            'Workloads → see KSI-IAM-SNU (replace with IAM role + IRSA / EC2 instance profile / Lambda execution role).',
            'Tag any documented exceptions (break-glass, legacy partner integration) with `purpose=...` and `exception_until=YYYY-MM-DD`.',
            'Delete migrated users.',
          ],
        }],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ac-2','ac-2.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Same migration effort.' },
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Workload IAM users become IAM roles, addressing SNU.' },
      ],
    }),

    finding({
      rule: 'aws.iam.no_access_keys_older_than_90d',
      passed: usersWithOldKeys.length === 0,
      severity: 'high',
      current: {
        summary: usersWithOldKeys.length === 0
          ? 'All IAM access keys are <90 days old (or there are none).'
          : `${usersWithOldKeys.length} access key(s) are older than 90 days.`,
        observations: { stale_keys: usersWithOldKeys },
      },
      target: {
        summary: 'No IAM access key is older than 90 days. Ideally no long-lived access keys exist at all (use IAM roles + STS).',
        rationale: 'NIST IA-5(1) requires authenticator rotation. Long-lived access keys are the #1 source of cloud credential compromise.',
      },
      gap: usersWithOldKeys.length === 0 ? undefined : {
        description: 'Stale access keys are routinely used as initial-access vectors. Each listed key should be rotated and ideally replaced with a role.',
        affected_resources: usersWithOldKeys.map<AffectedResource>((k) => ({
          type: 'aws_iam_access_key',
          identifier: k.keyId,
          name: `${k.user}: ${k.keyId}`,
          attributes: { user: k.user, ageDays: k.ageDays },
        })),
      },
      remediation: usersWithOldKeys.length === 0 ? undefined : {
        summary: 'For each stale key: rotate immediately, then plan replacement with IAM-role-based authentication.',
        options: [
          {
            approach: 'Rotate the access key (short-term).',
            mechanism: 'cli',
            owner_team: 'SRE',
            cost_impact: { level: 'none', notes: 'No charge.' },
            availability_impact: { level: 'low', notes: 'Any workload using the old key needs the new key; coordinate downtime.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'hours', notes: 'Per key.' },
            steps: [
              'aws iam create-access-key --user-name <USER>',
              'Update the consuming workload to use the new key.',
              'Verify the workload is healthy on the new key.',
              'aws iam update-access-key --user-name <USER> --access-key-id <OLD_KEY> --status Inactive',
              'After a soak period, aws iam delete-access-key --user-name <USER> --access-key-id <OLD_KEY>',
            ],
          },
          {
            approach: 'Replace the access key with an IAM role + STS (long-term — preferred).',
            mechanism: 'terraform',
            owner_team: 'SRE',
            cost_impact: { level: 'none', notes: 'No charge.' },
            availability_impact: { level: 'medium', notes: 'Workload reconfiguration required.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'days', notes: 'Per workload.' },
            steps: [
              'See KSI-IAM-SNU for the workload-by-workload replacement playbook (IRSA for EKS, EC2 instance profile, Lambda execution role, IAM Roles Anywhere for off-cloud).',
            ],
            references: [
              { title: 'AWS docs: IAM Roles Anywhere', url: 'https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html' },
            ],
          },
        ],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-2.3','ia-5','ia-5.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Replacing access keys with roles is the SNU remediation.' },
        { ksi_id: 'KSI-SVC-ASM', relationship: 'shares-remediation', note: 'Automating credential rotation is part of secret management.' },
      ],
    }),

    finding({
      rule: 'aws.iam.no_password_users_without_mfa',
      passed: usersWithPasswordNoMfa.length === 0,
      severity: 'critical',
      current: {
        summary: usersWithPasswordNoMfa.length === 0
          ? 'No IAM users have a password without MFA.'
          : `${usersWithPasswordNoMfa.length} IAM user(s) have console passwords but no MFA — critical exposure.`,
        observations: { offenders: usersWithPasswordNoMfa },
      },
      target: {
        summary: 'Every IAM user with a console password also has an MFA device registered.',
        rationale: 'Direct credential-theft attack path. NIST IA-2(1) requires MFA for all interactive access.',
      },
      gap: usersWithPasswordNoMfa.length === 0 ? undefined : {
        description: 'These users can be fully compromised via password theft alone.',
        affected_resources: usersWithPasswordNoMfa.map<AffectedResource>((u) => ({
          type: 'aws_iam_user', identifier: `arn:aws:iam::${ctx.account}:user/${u}`, name: u, attributes: {},
        })),
      },
      remediation: usersWithPasswordNoMfa.length === 0 ? undefined : {
        summary: 'Apply force-MFA policy (see KSI-IAM-MFA Finding 2) immediately; then plan migration.',
        options: [
          { approach: 'See KSI-IAM-MFA Finding 2', mechanism: 'terraform', owner_team: 'Security', steps: ['Apply the force-MFA deny policy. Once MFA is enrolled, plan migration to Identity Center.'] },
        ],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ia-2.1','ia-2.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Same affected resources, same remediation.' },
      ],
    }),

    finding({
      rule: 'aws.access_analyzer.unused_access_findings_managed',
      passed: unusedAccessFindings <= 25,
      severity: 'medium',
      current: {
        summary: `${unusedAccessFindings} unused-access finding(s) from IAM Access Analyzer.`,
        observations: { count: unusedAccessFindings },
      },
      target: {
        summary: 'Unused-access findings stay below a defined threshold (default 25) and trend flat or down.',
        rationale: 'Persistent unused-access findings indicate over-granted permissions — a leading indicator of weak lifecycle hygiene.',
      },
      gap: unusedAccessFindings <= 25 ? undefined : {
        description: 'More than 25 unused-access findings suggest the org has accumulated dead-weight permissions.',
        affected_resources: [{ type: 'aws_accessanalyzer_analyzer', identifier: 'unused-access', attributes: { count: unusedAccessFindings } }],
      },
      remediation: unusedAccessFindings <= 25 ? undefined : {
        summary: 'Triage each finding; remove or justify.',
        options: [{
          approach: 'Open each finding in the IAM Access Analyzer console; either remove the unused access or document why it must remain.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'No charge.' },
          availability_impact: { level: 'low', notes: 'Removing permissions could break edge cases; test carefully.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-finding triage. Bulk patterns help.' },
          steps: ['Sort findings by severity.', 'For each, decide remove vs document.', 'Apply IaC change or mark exception.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','ac-6.5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'These findings are the primary input to ELP review cycles.' },
      ],
    }),

    finding({
      rule: 'aws.identity_center.abac_configured',
      passed: abacConfigured,
      severity: 'low',
      current: {
        summary: abacConfigured
          ? 'IAM Identity Center has Attribute-Based Access Control configured (uses IdP attributes in IAM conditions).'
          : 'ABAC is not configured. Permission sets are role-based only.',
        observations: { abacConfigured },
      },
      target: {
        summary: 'ABAC is enabled with at least one attribute mapped from the IdP (e.g. department, environment).',
        rationale: 'ABAC reduces permission-set sprawl and supports finer-grained access decisions. Not required by FedRAMP but signals mature identity engineering.',
      },
      gap: abacConfigured ? undefined : {
        description: 'Without ABAC you cannot tag-condition role assumptions per attribute, forcing a permission set per access pattern.',
        affected_resources: [{ type: 'aws_ssoadmin_instance_access_control_attributes', identifier: ctx.account ?? '', attributes: {} }],
      },
      remediation: abacConfigured ? undefined : {
        summary: 'Enable ABAC and map at least one IdP attribute (e.g. department).',
        options: [{
          approach: 'Configure ABAC via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Identity / IT',
          cost_impact: { level: 'none', notes: 'No charge.' },
          availability_impact: { level: 'low', notes: 'Permission sets continue to work; ABAC is additive.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Decide which attributes to map; pilot with one.' },
          steps: [
            'In your IdP, confirm the attributes you want available (Okta SAML attribute statements, Azure AD claims).',
            'Apply the Terraform below to map the attributes.',
            'Update permission-set policies to consume aws:PrincipalTag/Department etc. in Conditions.',
            'Test by signing in as a user in a tagged group and verifying the conditional access.',
          ],
          example_code: `resource "aws_ssoadmin_instance_access_control_attributes" "abac" {
  instance_arn = data.aws_ssoadmin_instances.this.arns[0]
  attribute { key = "Department"  value { source = ["\${path:enterprise.department}"] } }
  attribute { key = "Environment" value { source = ["\${path:enterprise.environment}"] } }
}`,
          references: [
            { title: 'AWS docs: ABAC in Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/abac.html' },
          ],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6'],
    }),
  ];

  // ---- 3rd-party tool detection ----
  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    iam_user_names: users.map((u) => u.UserName ?? ''),
    iam_role_names: [], // captured by other collectors
    identity_center_present: identityCenterInstances >= 1,
  });

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-APM — Adopting Passwordless / strong + MFA
// =====================================================================
export async function collectIamApm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // Password policy
  let passwordPolicy: any = null;
  try {
    const pp = await iamClient.send(new GetAccountPasswordPolicyCommand({}));
    passwordPolicy = pp.PasswordPolicy;
    evidence.push(ev('iam.GetAccountPasswordPolicy', passwordPolicy));
  } catch (e: any) {
    warnings.push(`GetAccountPasswordPolicy: ${e.message}`);
  }

  // Cognito user pools (app users)
  const cognitoPools: Array<{ id: string; name: string; mfa: string | undefined }> = [];
  try {
    const cog = aws.cognito(ctx.auth);
    let tok: string | undefined;
    do {
      const lst = await cog.send(new ListUserPoolsCommand({ MaxResults: 60, NextToken: tok }));
      for (const p of lst.UserPools ?? []) {
        if (!p.Id) continue;
        const detail = await cog.send(new DescribeUserPoolCommand({ UserPoolId: p.Id }));
        cognitoPools.push({ id: p.Id, name: p.Name ?? '', mfa: detail.UserPool?.MfaConfiguration });
      }
      tok = lst.NextToken;
    } while (tok);
    evidence.push(ev('cognito.user_pools_summary', cognitoPools));
  } catch (e: any) {
    warnings.push(`Cognito listing: ${e.message}`);
  }

  const cognitoNoMfa = cognitoPools.filter((p) => p.mfa !== 'ON');
  const passwordPolicyStrong = !!passwordPolicy &&
    (passwordPolicy.MinimumPasswordLength ?? 0) >= 14 &&
    !!passwordPolicy.RequireSymbols && !!passwordPolicy.RequireNumbers &&
    !!passwordPolicy.RequireUppercaseCharacters && !!passwordPolicy.RequireLowercaseCharacters &&
    (passwordPolicy.PasswordReusePrevention ?? 0) >= 12;

  const findings = [
    finding({
      rule: 'aws.iam.password_policy_strong',
      passed: passwordPolicyStrong,
      severity: 'high',
      current: {
        summary: passwordPolicy
          ? `Password policy: min length ${passwordPolicy.MinimumPasswordLength}, reuse prevention ${passwordPolicy.PasswordReusePrevention}, symbols=${passwordPolicy.RequireSymbols}, numbers=${passwordPolicy.RequireNumbers}, upper=${passwordPolicy.RequireUppercaseCharacters}, lower=${passwordPolicy.RequireLowercaseCharacters}.`
          : 'No account password policy is configured (defaults are weak).',
        observations: passwordPolicy ?? null,
      },
      target: {
        summary: 'Min length ≥ 14, all complexity flags set, password reuse prevention ≥ 12 generations.',
        rationale: 'NIST IA-5(1) requires authenticator complexity. Phishing-resistant MFA is the goal (KSI-IAM-MFA), but where passwords exist as the fallback they must be strong.',
      },
      gap: passwordPolicyStrong ? undefined : {
        description: 'Current policy is weaker than the FedRAMP-aligned baseline (length ≥14, full complexity, reuse ≥12).',
        affected_resources: [{ type: 'aws_iam_account_password_policy', identifier: ctx.account ?? '', attributes: passwordPolicy ?? {} }],
      },
      remediation: passwordPolicyStrong ? undefined : {
        summary: 'Set the IAM account password policy to FedRAMP-aligned thresholds via Terraform.',
        options: [{
          approach: 'Apply strict IAM password policy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'No charge.' },
          availability_impact: { level: 'low', notes: 'Existing passwords keep working until next change; users will see new requirements on next reset.' },
          customer_visible: { level: 'none', notes: 'Affects internal IAM users only — not Cognito app users.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform; document the policy in your security baseline.' },
          steps: [
            'Apply the Terraform below.',
            'Confirm via `aws iam get-account-password-policy`.',
            'Communicate to any remaining IAM users.',
          ],
          example_code: `resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 12
  max_password_age               = 90
  allow_users_to_change_password = true
  hard_expiry                    = false
}`,
          references: [{ title: 'AWS docs: IAM password policy', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-5','ia-5.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'Migration to Identity Center deprecates IAM passwords entirely; preferred long-term.' },
      ],
    }),

    finding({
      rule: 'aws.cognito.app_pools_mfa_required',
      passed: cognitoNoMfa.length === 0,
      severity: 'high',
      current: {
        summary: cognitoPools.length === 0
          ? 'No Cognito user pools detected (N/A for this KSI on AWS-Cognito side).'
          : (cognitoNoMfa.length === 0
            ? `All ${cognitoPools.length} Cognito user pool(s) have MFA enforced.`
            : `${cognitoNoMfa.length} of ${cognitoPools.length} Cognito user pool(s) do not enforce MFA.`),
        observations: cognitoPools,
      },
      target: { summary: 'Every Cognito user pool that authenticates federal end-users has MfaConfiguration=ON.', rationale: 'NIST IA-2(1) for application end-users.' },
      gap: cognitoNoMfa.length === 0 ? undefined : {
        description: 'Cognito user pools without MFA expose app end-users to credential theft.',
        affected_resources: cognitoNoMfa.map<AffectedResource>((p) => ({ type: 'aws_cognito_user_pool', identifier: p.id, name: p.name, attributes: { current_mfa: p.mfa ?? 'OFF' } })),
      },
      remediation: cognitoNoMfa.length === 0 ? undefined : {
        summary: 'Set MfaConfiguration to ON for each user pool. Coordinate with product team since this affects sign-in UX.',
        options: [{
          approach: 'Set MfaConfiguration=ON via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Product',
          cost_impact: { level: 'low', notes: 'SMS MFA incurs per-message charges; TOTP is free.' },
          availability_impact: { level: 'medium', notes: 'Existing users challenged to enroll MFA on next sign-in.' },
          customer_visible: { level: 'high', notes: 'Agency end-users see a new MFA enrollment flow. Coordinate communication.' },
          effort_estimate: { magnitude: 'days', notes: 'Pool config is quick; user comms + support is the long tail.' },
          steps: [
            'Decide MFA factors per pool (TOTP preferred for phishing-resistance; SMS allowed but not phishing-resistant).',
            'Apply Terraform.',
            'Communicate to end users before rollout.',
          ],
          example_code: `resource "aws_cognito_user_pool" "main" {
  name                     = "agency-customers"
  mfa_configuration        = "ON"
  software_token_mfa_configuration { enabled = true }
  account_recovery_setting {
    recovery_mechanism { name = "verified_email" priority = 1 }
  }
}`,
          references: [{ title: 'AWS docs: Cognito user pool MFA', url: 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-2','ia-2.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-AFR-SCG', relationship: 'shares-remediation', note: 'Cognito MFA settings should be documented in the customer-facing Secure Configuration Guide.' },
      ],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-ELP — Ensuring Least Privilege
// =====================================================================
export async function collectIamElp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // Wildcard scan in customer-managed policies
  const wildcardPolicies: Array<{ policyArn: string; statementIdx: number; action: unknown; resource: unknown }> = [];
  let policyCount = 0;
  try {
    let marker: string | undefined;
    do {
      const out = await iamClient.send(new ListPoliciesCommand({ Scope: 'Local', Marker: marker, MaxItems: 100 }));
      for (const p of out.Policies ?? []) {
        if (!p.Arn || !p.DefaultVersionId) continue;
        policyCount++;
        try {
          const v = await iamClient.send(new GetPolicyVersionCommand({ PolicyArn: p.Arn, VersionId: p.DefaultVersionId }));
          // GetPolicyVersion returns the doc URL-encoded; defensive parse so a
          // malformed/truncated policy doesn't crash the whole collector.
          let doc: any = { Statement: [] };
          try {
            const decoded = decodeURIComponent(v.PolicyVersion?.Document ?? '{}');
            doc = JSON.parse(decoded);
          } catch (parseErr: any) {
            warnings.push(`GetPolicyVersion ${p.Arn}: malformed policy JSON: ${parseErr.message}`);
            continue;
          }
          const stmts: any[] = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement].filter(Boolean);
          stmts.forEach((s, i) => {
            const allow = s.Effect === 'Allow';
            const allActions = s.Action === '*' || (Array.isArray(s.Action) && s.Action.includes('*'));
            const allResources = s.Resource === '*' || (Array.isArray(s.Resource) && s.Resource.includes('*'));
            if (allow && allActions && allResources && !s.Condition) {
              wildcardPolicies.push({ policyArn: p.Arn!, statementIdx: i, action: s.Action, resource: s.Resource });
            }
          });
        } catch (e: any) {
          warnings.push(`GetPolicyVersion ${p.Arn}: ${e.message}`);
        }
      }
      { const _nm = out.IsTruncated ? out.Marker : undefined; marker = _nm === marker ? undefined : _nm; }
    } while (marker);
  } catch (e: any) {
    warnings.push(`ListPolicies: ${e.message}`);
  }
  evidence.push(ev('iam.customer_managed_policy_scan', { policy_count: policyCount, wildcards: wildcardPolicies }));

  // Roles + stale-use sample
  const staleRoles: Array<{ role: string; daysSinceLastUse: number }> = [];
  let roleCount = 0;
  try {
    let marker: string | undefined;
    do {
      const out = await iamClient.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
      for (const r of out.Roles ?? []) {
        roleCount++;
        const last = r.RoleLastUsed?.LastUsedDate;
        if (last) {
          const days = await ageInDays(last) ?? 0;
          if (days > 90) staleRoles.push({ role: r.RoleName ?? '?', daysSinceLastUse: days });
        }
      }
      { const _nm = out.IsTruncated ? out.Marker : undefined; marker = _nm === marker ? undefined : _nm; }
    } while (marker);
  } catch (e: any) {
    warnings.push(`ListRoles: ${e.message}`);
  }
  evidence.push(ev('iam.role_inventory', { role_count: roleCount, stale_role_count: staleRoles.length, stale_sample: staleRoles.slice(0, 10) }));

  const findings = [
    finding({
      rule: 'aws.iam.no_unconditional_admin_wildcards',
      passed: wildcardPolicies.length === 0,
      severity: 'critical',
      current: {
        summary: wildcardPolicies.length === 0
          ? `No customer-managed policies have unconditional Action:* Resource:* Allow statements across ${policyCount} policies.`
          : `${wildcardPolicies.length} statement(s) in customer-managed policies grant unconditional admin (Action:* Resource:* Allow without Condition).`,
        observations: { policy_count: policyCount, wildcard_statements: wildcardPolicies },
      },
      target: { summary: 'Zero customer-managed policies with unconditional Action:*/Resource:*/Effect:Allow.', rationale: 'NIST AC-6 (least privilege). Unconditional admin makes every other IAM control meaningless.' },
      gap: wildcardPolicies.length === 0 ? undefined : {
        description: 'Each wildcard policy is an Admin grant.',
        affected_resources: wildcardPolicies.map<AffectedResource>((w) => ({
          type: 'aws_iam_policy', identifier: w.policyArn, name: w.policyArn.split('/').pop() ?? w.policyArn,
          attributes: { statement_index: w.statementIdx, action: w.action, resource: w.resource },
        })),
      },
      remediation: wildcardPolicies.length === 0 ? undefined : {
        summary: 'Replace each wildcard statement with a scoped Action list + scoped Resource ARNs, OR delete if unused.',
        options: [{
          approach: 'Audit consumers + replace with scoped policy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Risk of denying legitimate access if scope is too tight. Use Access Advisor to inform.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per policy; needs consumer review.' },
          steps: [
            'For each wildcard policy, identify attached principals (`iam:ListEntitiesForPolicy`).',
            'For each principal, run `iam:GetServiceLastAccessedDetails` to find services actually used.',
            'Draft scoped policy enumerating only required actions/resources.',
            'Roll out the new policy alongside the wildcard; verify; remove the wildcard.',
          ],
          example_code: `data "aws_iam_policy_document" "scoped" {
  statement {
    actions   = ["s3:GetObject","s3:PutObject"]
    resources = ["arn:aws:s3:::your-prod-bucket/*"]
  }
}
resource "aws_iam_policy" "scoped" {
  name   = "scoped-replacement"
  policy = data.aws_iam_policy_document.scoped.json
}`,
          references: [{ title: 'AWS docs: IAM Access Advisor', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','ac-6.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-DFP', relationship: 'shares-remediation', note: 'Same hygiene problem at IAM-policy + SCP level.' },
      ],
    }),

    finding({
      rule: 'aws.iam.role_inventory_clean',
      passed: staleRoles.length <= 20,
      severity: 'medium',
      current: {
        summary: `${roleCount} IAM roles total; ${staleRoles.length} unused for >90 days.`,
        observations: { role_count: roleCount, stale_roles: staleRoles },
      },
      target: { summary: 'Stale-role count below threshold (default 20). Trending down over time.', rationale: 'Stale roles accumulate permissions. NIST AC-2(3) requires disabling unused accounts.' },
      gap: staleRoles.length <= 20 ? undefined : {
        description: 'Roles unused for >90 days should be reviewed and either documented (break-glass) or deleted.',
        affected_resources: staleRoles.map<AffectedResource>((r) => ({
          type: 'aws_iam_role', identifier: `arn:aws:iam::${ctx.account}:role/${r.role}`, name: r.role,
          attributes: { days_since_last_use: r.daysSinceLastUse },
        })),
      },
      remediation: staleRoles.length <= 20 ? undefined : {
        summary: 'Triage stale roles; delete or document each.',
        options: [{
          approach: 'Review each stale role.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Deleting an in-use role breaks consumers; verify with Access Advisor / CloudTrail first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per role.' },
          steps: ['Sort by days_since_last_use desc.', 'For each, decide: delete, document exception, or restore use.', 'Apply IaC change.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-2','ac-2.3'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Stale-role hygiene is part of account-lifecycle automation.' },
      ],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-JIT — Authorizing Just-in-Time
// =====================================================================
export async function collectIamJit(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  const ssoa = aws.ssoadmin(ctx.auth);
  const psWithLongSessions: Array<{ permissionSet: string; sessionDuration: string }> = [];
  let allPermSets = 0;
  try {
    const insts = await ssoa.send(new ListInstancesCommand({}));
    for (const inst of insts.Instances ?? []) {
      if (!inst.InstanceArn) continue;
      let tok: string | undefined;
      do {
        const ps = await ssoa.send(new ListPermissionSetsCommand({ InstanceArn: inst.InstanceArn, NextToken: tok }));
        for (const psArn of ps.PermissionSets ?? []) {
          allPermSets++;
          const d = await ssoa.send(new DescribePermissionSetCommand({ InstanceArn: inst.InstanceArn, PermissionSetArn: psArn }));
          const dur = d.PermissionSet?.SessionDuration ?? 'PT8H';
          // ISO 8601 duration; "PT8H" = 8h. We accept <=8h; longer is suspicious.
          if (!/^PT[1-8]H$/.test(dur) && dur !== 'PT15M' && dur !== 'PT30M' && dur !== 'PT45M' && dur !== 'PT1H' && dur !== 'PT2H' && dur !== 'PT4H' && dur !== 'PT8H' && !/^PT(?:1[0-9]|[1-9])M$/.test(dur)) {
            psWithLongSessions.push({ permissionSet: d.PermissionSet?.Name ?? psArn, sessionDuration: dur });
          }
        }
        tok = ps.NextToken;
      } while (tok);
    }
    evidence.push(ev('sso-admin.permission_set_session_durations', { count: allPermSets, exceeding_8h: psWithLongSessions }));
  } catch (e: any) {
    warnings.push(`Permission set inspection: ${e.message}`);
  }

  // Session Manager recent sessions
  let recentSmSessions = 0;
  try {
    const ssm = aws.ssm(ctx.auth);
    const out = await ssm.send(new DescribeSessionsCommand({ State: 'History', MaxResults: 50 }));
    recentSmSessions = out.Sessions?.length ?? 0;
    evidence.push(ev('ssm.DescribeSessions(History)', { recent_sessions: recentSmSessions }));
  } catch (e: any) {
    warnings.push(`SSM DescribeSessions: ${e.message}`);
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Teleport / ConductorOne / StrongDM (3rd-party JIT tool)',
      description: 'JIT access can be governed by a 3rd-party tool that issues short-lived AWS credentials via STS AssumeRole. Evidence then lives in that tool, not in IAM Identity Center session durations.',
      evidence_required: ['JIT tool admin console export of recent grants/revokes', 'IAM role trust policy showing the JIT-tool principal', 'Sample audit log showing time-bound access'],
      detected: false, // populated by detector
      detection_signals: ['Will populate from third_party_tools_detected after enumeration'],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.identity_center.permission_set_session_duration_<=8h',
      passed: psWithLongSessions.length === 0,
      severity: 'high',
      current: {
        summary: psWithLongSessions.length === 0
          ? `All ${allPermSets} permission set(s) have SessionDuration <= 8 hours.`
          : `${psWithLongSessions.length} permission set(s) have SessionDuration > 8 hours.`,
        observations: { all_permission_sets: allPermSets, long_sessions: psWithLongSessions },
      },
      target: { summary: 'No permission set has SessionDuration > 8h. Privileged permission sets target ≤ 1h.', rationale: 'NIST AC-6(7) — periodic review/refresh of privileged access. Long sessions defeat JIT.' },
      gap: psWithLongSessions.length === 0 ? undefined : {
        description: 'Long permission-set sessions allow privileged credentials to live in caches and shell environments for too long.',
        affected_resources: psWithLongSessions.map<AffectedResource>((p) => ({
          type: 'aws_ssoadmin_permission_set', identifier: p.permissionSet, name: p.permissionSet,
          attributes: { session_duration: p.sessionDuration },
        })),
      },
      remediation: psWithLongSessions.length === 0 ? undefined : {
        summary: 'Reduce SessionDuration on each long-session permission set via Terraform.',
        options: [{
          approach: 'Tighten SessionDuration in Identity Center permission set Terraform.',
          mechanism: 'terraform',
          owner_team: 'Identity / IT',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Users see a re-auth challenge sooner; coordinate with developer workflows that assume long-lived sessions.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform; communicate to users.' },
          steps: ['Identify the long-session permission sets.', 'Update SessionDuration in IaC.', 'Apply; communicate.'],
          example_code: `resource "aws_ssoadmin_permission_set" "admin" {
  name             = "AdminAccess"
  instance_arn     = data.aws_ssoadmin_instances.this.arns[0]
  session_duration = "PT1H"   # was PT8H — tightened for privileged use
}`,
          references: [{ title: 'AWS docs: SessionDuration', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/howtosessionduration.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ac-2','ac-6.7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'depends-on', note: 'JIT is meaningful only on a least-privilege baseline.' },
      ],
    }),

    finding({
      rule: 'aws.ssm.session_manager_used_for_shell_access',
      passed: recentSmSessions > 0,
      severity: 'medium',
      current: {
        summary: recentSmSessions > 0
          ? `${recentSmSessions} recent SSM Session Manager session(s) found — indicates ephemeral shell access is in use.`
          : 'No recent SSM Session Manager sessions. Either nobody uses shell access (likely fine for serverless workloads) OR admins SSH directly with long-lived keys (bad).',
        observations: { recent_sessions: recentSmSessions },
      },
      target: { summary: 'Either no shell access is needed, OR all shell access is via SSM Session Manager (no inbound SSH).', rationale: 'Session Manager produces audit-logged, time-bound shell sessions without SSH keys. NIST AC-17 (remote access).' },
      gap: recentSmSessions > 0 ? undefined : {
        description: 'Without recent SSM sessions, we can\'t verify shell-access discipline. Cross-check whether the org runs instances at all (serverless workloads may have zero shell access by design).',
        affected_resources: [{ type: 'aws_ssm_session', identifier: 'no-recent-sessions', attributes: {} }],
      },
      remediation: recentSmSessions > 0 ? undefined : {
        summary: 'If you have EC2 instances, enable Session Manager and remove SSH ingress.',
        options: [{
          approach: 'Enable Session Manager via instance profile + remove port 22 SG rules.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Operators must switch from SSH to SSM; coordinate.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-fleet enablement.' },
          steps: [
            'Attach AmazonSSMManagedInstanceCore to the instance role.',
            'Ensure SSM Agent is installed (default on AL2/AL2023).',
            'Test `aws ssm start-session --target i-...`.',
            'Remove port 22 SG ingress.',
          ],
          references: [{ title: 'AWS docs: Session Manager', url: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: 'Serverless workloads (no EC2 / no shell access)', description: 'If you have no IaaS instances, this finding is moot.', evidence_required: ['Inventory showing zero in-scope EC2/ECS instances'], detected: false },
      ],
      nist_controls: ['ac-17','au-2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'Removing SSH ingress is also an MAT win.' },
      ],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({});
  // Propagate JIT-tool detection into alternative satisfiers
  const jitToolDetected = thirdParty.some((t) => /Teleport|ConductorOne|StrongDM/.test(t.name));
  if (jitToolDetected) {
    altSatisfiers[0]!.detected = true;
    altSatisfiers[0]!.detection_signals = thirdParty.filter((t) => /Teleport|ConductorOne|StrongDM/.test(t.name)).flatMap((t) => t.detection_signals);
  }

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
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
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // ---- Capture base context ----
  let accountAlias: string | null = null;
  try {
    const al = await iamClient.send(new ListAccountAliasesCommand({}));
    accountAlias = al.AccountAliases?.[0] ?? null;
    evidence.push(ev('iam.ListAccountAliases', { aliases: al.AccountAliases ?? [] }));
  } catch (e: any) {
    warnings.push(`ListAccountAliases: ${e.message}`);
  }

  // ---- Root account MFA status ----
  let summaryMap: any = {};
  try {
    const sum = await iamClient.send(new GetAccountSummaryCommand({}));
    summaryMap = sum.SummaryMap ?? {};
    evidence.push(ev('iam.GetAccountSummary', summaryMap));
  } catch (e: any) {
    warnings.push(`GetAccountSummary: ${e.message}`);
  }
  const rootMfaEnabled = summaryMap.AccountMFAEnabled === 1;
  const accountSigningCertsPresent = (summaryMap.AccountSigningCertificatesPresent ?? 0) > 0;

  // ---- IAM users + per-user MFA + attached policies + console-access flag ----
  interface UserRecord {
    UserName: string;
    Arn: string;
    UserId: string;
    CreateDate?: Date;
    PasswordLastUsed?: Date;
    hasConsoleLogin: boolean;
    mfaDevices: Array<{ SerialNumber?: string; EnableDate?: Date }>;
    attachedPolicies: string[];     // policy ARNs
    inlinePolicies: string[];        // policy names
    tags?: Record<string, string>;
  }

  const userRecords: UserRecord[] = [];
  const users = await listAllIamUsers(ctx);
  for (const u of users) {
    if (!u.UserName) continue;
    const rec: UserRecord = {
      UserName: u.UserName,
      Arn: '',
      UserId: '',
      CreateDate: u.CreateDate,
      PasswordLastUsed: u.PasswordLastUsed,
      hasConsoleLogin: false,
      mfaDevices: [],
      attachedPolicies: [],
      inlinePolicies: [],
    };
    try {
      const detail = await iamClient.send(new GetUserCommand({ UserName: u.UserName }));
      rec.Arn = detail.User?.Arn ?? '';
      rec.UserId = detail.User?.UserId ?? '';
      rec.tags = Object.fromEntries((detail.User?.Tags ?? []).map((t: any) => [t.Key, t.Value]));
    } catch (e: any) { warnings.push(`GetUser ${u.UserName}: ${e.message}`); }
    try {
      await iamClient.send(new GetLoginProfileCommand({ UserName: u.UserName }));
      rec.hasConsoleLogin = true;
    } catch (e: any) {
      if (!/NoSuchEntity/.test(e.name ?? e.message ?? '')) {
        warnings.push(`GetLoginProfile ${u.UserName}: ${e.message}`);
      }
    }
    try {
      const mfa = await iamClient.send(new ListMFADevicesCommand({ UserName: u.UserName }));
      rec.mfaDevices = (mfa.MFADevices ?? []).map((d) => ({ SerialNumber: d.SerialNumber, EnableDate: d.EnableDate }));
    } catch (e: any) { warnings.push(`ListMFADevices ${u.UserName}: ${e.message}`); }
    try {
      const attached = await iamClient.send(new ListAttachedUserPoliciesCommand({ UserName: u.UserName }));
      rec.attachedPolicies = (attached.AttachedPolicies ?? []).map((p) => p.PolicyArn ?? '').filter(Boolean);
    } catch (e: any) { warnings.push(`ListAttachedUserPolicies ${u.UserName}: ${e.message}`); }
    try {
      const inline = await iamClient.send(new ListUserPoliciesCommand({ UserName: u.UserName }));
      rec.inlinePolicies = inline.PolicyNames ?? [];
    } catch (e: any) { warnings.push(`ListUserPolicies ${u.UserName}: ${e.message}`); }
    userRecords.push(rec);
  }
  evidence.push(ev('iam.user_inventory_full', userRecords));

  // ---- Virtual MFA devices (TOTP — NOT phishing-resistant) ----
  let virtualMfaDevices: Array<{ SerialNumber?: string; User?: any; EnableDate?: Date }> = [];
  try {
    const vm = await iamClient.send(new ListVirtualMFADevicesCommand({}));
    virtualMfaDevices = (vm.VirtualMFADevices ?? []).map((d) => ({
      SerialNumber: d.SerialNumber,
      User: d.User?.UserName ? { UserName: d.User.UserName, Arn: d.User.Arn } : null,
      EnableDate: d.EnableDate,
    }));
    evidence.push(ev('iam.ListVirtualMFADevices', virtualMfaDevices));
  } catch (e: any) {
    warnings.push(`ListVirtualMFADevices: ${e.message}`);
  }

  // ---- SAML / OIDC identity providers (alternative-satisfier detection) ----
  let samlProviders: string[] = [];
  let oidcProviders: string[] = [];
  try {
    const s = await iamClient.send(new ListSAMLProvidersCommand({}));
    samlProviders = (s.SAMLProviderList ?? []).map((p) => p.Arn ?? '').filter(Boolean);
    evidence.push(ev('iam.ListSAMLProviders', samlProviders));
  } catch (e: any) { warnings.push(`ListSAMLProviders: ${e.message}`); }
  try {
    const o = await iamClient.send(new ListOpenIDConnectProvidersCommand({}));
    oidcProviders = (o.OpenIDConnectProviderList ?? []).map((p) => p.Arn ?? '').filter(Boolean);
    evidence.push(ev('iam.ListOpenIDConnectProviders', oidcProviders));
  } catch (e: any) { warnings.push(`ListOpenIDConnectProviders: ${e.message}`); }

  // ---- IAM Identity Center external IdP (alternative-satisfier detection) ----
  let identityCenterPresent = false;
  let identityCenterInstanceArn: string | null = null;
  try {
    const ssoa = aws.ssoadmin(ctx.auth);
    const insts = await ssoa.send(new ListInstancesCommand({}));
    if ((insts.Instances ?? []).length > 0) {
      identityCenterPresent = true;
      identityCenterInstanceArn = insts.Instances?.[0]?.InstanceArn ?? null;
    }
    evidence.push(ev('sso-admin.ListInstances', insts.Instances ?? []));
  } catch (e: any) { warnings.push(`SSO ListInstances: ${e.message}`); }

  // ---- SCP scan: any SCP attached at org level denying actions when MFA not present? ----
  interface ScpRecord { id: string; name: string; type: string; arn: string; content: string; }
  const allScps: ScpRecord[] = [];
  const scpsWithMfaDeny: ScpRecord[] = [];
  let orgReachable = true;
  try {
    const org = aws.organizations(ctx.auth);
    let tok: string | undefined;
    do {
      const ps = await org.send(new OrgListPoliciesCommand({ Filter: 'SERVICE_CONTROL_POLICY', NextToken: tok, MaxResults: 20 }));
      for (const p of ps.Policies ?? []) {
        if (!p.Id) continue;
        try {
          const d = await org.send(new OrgDescribePolicyCommand({ PolicyId: p.Id }));
          const rec: ScpRecord = {
            id: p.Id,
            name: p.Name ?? '',
            type: p.Type ?? '',
            arn: p.Arn ?? '',
            content: d.Policy?.Content ?? '',
          };
          allScps.push(rec);
          if (/MultiFactorAuthPresent/i.test(rec.content) && /"Deny"/.test(rec.content)) {
            scpsWithMfaDeny.push(rec);
          }
        } catch (e: any) {
          warnings.push(`DescribePolicy ${p.Id}: ${e.message}`);
        }
      }
      tok = ps.NextToken;
    } while (tok);
    evidence.push(ev('organizations.scp_inventory', {
      total: allScps.length,
      with_mfa_deny: scpsWithMfaDeny.map((s) => ({ id: s.id, name: s.name })),
    }));
  } catch (e: any) {
    orgReachable = false;
    warnings.push(`Organizations API not reachable (not a member account, or missing AWSOrganizationsReadOnlyAccess?): ${e.message}`);
  }

  // ---- Compose alternative satisfiers ----
  const externalIdpDetected = samlProviders.length > 0 || oidcProviders.length > 0 || identityCenterPresent;
  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External SAML/OIDC IdP (Okta, Azure AD, Google Workspace, etc.)',
      description: 'When sign-in is federated, phishing-resistant MFA is enforced upstream by the IdP rather than within AWS. AWS still requires root MFA, but standalone IAM user MFA is not a meaningful gate when no humans use IAM users.',
      evidence_required: [
        'IdP MFA enforcement policy export (e.g. Okta "Authentication Policy" rules requiring WebAuthn for AWS app)',
        'List of users in scope of the AWS access app within the IdP',
        'Sample sign-in log showing WebAuthn was used',
      ],
      detected: externalIdpDetected,
      detection_signals: [
        ...(samlProviders.length ? [`SAML providers: ${samlProviders.length} registered`] : []),
        ...(oidcProviders.length ? [`OIDC providers: ${oidcProviders.length} registered`] : []),
        ...(identityCenterPresent ? [`IAM Identity Center instance present: ${identityCenterInstanceArn}`] : []),
        ...((!samlProviders.length && !oidcProviders.length && !identityCenterPresent) ? ['No SAML/OIDC providers; no Identity Center instance.'] : []),
      ],
    },
    {
      via: 'IAM Identity Center managing all human access (no standalone IAM users)',
      description: 'If every human accesses AWS via Identity Center (federated from an IdP), no standalone IAM users should exist, and MFA is enforced by the IdP or by Identity Center itself.',
      evidence_required: [
        'Identity Center MFA configuration screenshot',
        'List of permission sets used in prod accounts',
      ],
      detected: identityCenterPresent && users.length === 0,
      detection_signals: identityCenterPresent
        ? [`Identity Center present; IAM users found: ${users.length} (target 0)`]
        : ['Identity Center not present.'],
    },
  ];

  // ---- Findings ----

  const usersWithoutMfa = userRecords.filter((u) => u.hasConsoleLogin && u.mfaDevices.length === 0);
  const usersOnVirtualMfa = userRecords.filter((u) => u.mfaDevices.some((d) => /:mfa\//.test(d.SerialNumber ?? '')));

  const findings = [
    // ----- Finding 1: Root MFA -----
    finding({
      rule: 'aws.iam.root_mfa_enabled',
      passed: rootMfaEnabled,
      severity: 'critical',
      current: {
        summary: rootMfaEnabled
          ? `Root MFA is enabled on account ${ctx.account}${accountAlias ? ` (${accountAlias})` : ''}.`
          : `Root MFA is NOT enabled on account ${ctx.account}${accountAlias ? ` (${accountAlias})` : ''}.`,
        observations: {
          account_id: ctx.account,
          account_alias: accountAlias,
          AccountMFAEnabled: summaryMap.AccountMFAEnabled,
          AccountSigningCertificatesPresent: accountSigningCertsPresent,
        },
      },
      target: {
        summary: 'Root account has a hardware (FIDO2/security-key) MFA device registered.',
        rationale: 'The root account is the highest-privilege identity in any AWS account. FedRAMP requires phishing-resistant MFA for all privileged human authentication (NIST IA-2(1), IA-2(6)). A virtual MFA on root is insufficient; a hardware MFA is the FedRAMP-acceptable bar.',
      },
      gap: rootMfaEnabled ? undefined : {
        description: 'Root account does not have an MFA device registered. Anyone who recovers the root credential can take full control of the account.',
        affected_resources: [
          { type: 'aws_account_root_user', identifier: ctx.account ?? 'unknown-account', attributes: { account_alias: accountAlias } },
        ],
      },
      remediation: rootMfaEnabled ? undefined : {
        summary: 'Enable a hardware MFA device on the root user. This must be done manually in the console; there is no AWS API to set root MFA.',
        options: [
          {
            approach: 'Register a hardware MFA device for root via the AWS console (recommended).',
            mechanism: 'console',
            owner_team: 'Identity / IT',
            cost_impact: { level: 'low', notes: 'One-time hardware key purchase (~$50-$100 per key); recommend buying 2 for redundancy.' },
            availability_impact: { level: 'none', notes: 'No service impact; root account is not used for routine operations.' },
            customer_visible: { level: 'none', notes: 'Not customer-facing.' },
            effort_estimate: { magnitude: 'hours', notes: '15 minutes per account once hardware is in hand; coordinate across accounts in the org.' },
            prerequisites: [
              'A physical FIDO2 security key (e.g. YubiKey 5 series) or a virtual MFA app on a dedicated, secured device.',
              'Access to the root email account for sign-in challenge.',
            ],
            steps: [
              'Sign in to the AWS Console using the root user (email + password).',
              'Open IAM > Security credentials (root identity).',
              'Under Multi-factor authentication (MFA), choose Assign MFA device.',
              'Select FIDO security key as the device type, name it, and follow the registration flow.',
              'Sign out and sign back in with root + WebAuthn to confirm the new factor.',
              'Store the recovery procedure in your break-glass runbook.',
            ],
            side_effects: [
              'Every subsequent root sign-in will require physical presence + WebAuthn touch.',
              'Lost keys require AWS Support recovery — keep a backup hardware key.',
            ],
            references: [
              { title: 'AWS docs: Enable a virtual MFA device for your AWS account root user', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html' },
              { title: 'AWS docs: Enabling a FIDO security key', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_fido.html' },
            ],
          },
          {
            approach: 'Use AWS Control Tower / Account Factory enrollment that requires root MFA at account-creation time.',
            mechanism: 'process',
            owner_team: 'Platform',
            cost_impact: { level: 'medium', notes: 'Control Tower itself is free but the underlying services it provisions (Organizations, Config, CloudTrail) accrue normal usage charges.' },
            availability_impact: { level: 'none', notes: 'Greenfield only; no impact to existing accounts.' },
            customer_visible: { level: 'none', notes: 'Not customer-facing.' },
            effort_estimate: { magnitude: 'days', notes: 'Establishing Control Tower from scratch is a multi-day project; only worthwhile if also addressing AAM/ELP at the same time.' },
            steps: [
              'For greenfield accounts, enrol them via Control Tower with the Account Factory blueprint requiring MFA before delegated access is granted.',
              'For brownfield, apply the console approach above; Control Tower cannot retroactively force root MFA.',
            ],
            references: [
              { title: 'AWS Control Tower Account Factory', url: 'https://docs.aws.amazon.com/controltower/latest/userguide/account-factory.html' },
            ],
          },
        ],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-2.1','ia-2.6'],
      references: [
        { title: 'FedRAMP 20x KSI-IAM-MFA', url: 'https://www.fedramp.gov/20x/' },
      ],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-AFR-UCM', relationship: 'depends-on', note: 'WebAuthn / FIDO2 modules used here must appear in the UCM cryptographic-module rationale.' },
      ],
      compliance_blockers: rootMfaEnabled ? [] : [
        'Hardware security keys must be procured and physically held by named root-credential custodians.',
      ],
    }),

    // ----- Finding 2: Standalone-IAM-user MFA -----
    finding({
      rule: 'aws.iam.console_users_have_mfa',
      passed: usersWithoutMfa.length === 0,
      severity: 'critical',
      current: {
        summary: usersWithoutMfa.length === 0
          ? `Every console-enabled IAM user has at least one MFA device.`
          : `${usersWithoutMfa.length} of ${userRecords.length} IAM users have a console password but no MFA device.`,
        observations: {
          total_iam_users: userRecords.length,
          console_enabled_users: userRecords.filter((u) => u.hasConsoleLogin).length,
          users_without_mfa: usersWithoutMfa.map((u) => ({
            UserName: u.UserName,
            Arn: u.Arn,
            CreateDate: u.CreateDate,
            PasswordLastUsed: u.PasswordLastUsed,
            attachedPolicies: u.attachedPolicies,
            inlinePolicies: u.inlinePolicies,
            tags: u.tags,
          })),
        },
      },
      target: {
        summary: 'Zero console-enabled IAM users without phishing-resistant MFA. Ideally zero standalone IAM users at all (federate via Identity Center / IdP).',
        rationale: 'NIST IA-2 / IA-2(1) require MFA for all interactive access. FedRAMP 20x specifically calls for phishing-resistant MFA (KSI-IAM-MFA).',
      },
      gap: usersWithoutMfa.length === 0 ? undefined : {
        description: 'Console-enabled IAM users without MFA can be compromised through credential theft alone. Each user listed below should either have MFA registered, be migrated to Identity Center, or be deleted if no longer needed.',
        affected_resources: usersWithoutMfa.map<AffectedResource>((u) => ({
          type: 'aws_iam_user',
          identifier: u.Arn,
          name: u.UserName,
          attributes: {
            CreateDate: u.CreateDate,
            PasswordLastUsed: u.PasswordLastUsed,
            attachedPolicies: u.attachedPolicies,
            inlinePolicies: u.inlinePolicies,
          },
          tags: u.tags,
        })),
      },
      remediation: usersWithoutMfa.length === 0 ? undefined : {
        summary: 'Force MFA enrollment via IAM policy (short-term) and migrate to Identity Center (long-term). If the listed users are humans, migrate them to your IdP; if they are service accounts misclassified as users, replace with IAM roles + IRSA / Workload Identity.',
        options: [
          {
            approach: 'Attach a deny-without-MFA policy boundary so users cannot do anything until they enroll MFA.',
            mechanism: 'terraform',
            owner_team: 'Security',
            cost_impact: { level: 'none', notes: 'No additional AWS charges.' },
            availability_impact: { level: 'medium', notes: 'Affected users are locked out of API + console until they self-enroll MFA. Pre-announce with deadline.' },
            customer_visible: { level: 'none', notes: 'Only affects internal users with standalone IAM access; agency customers do not see this change.' },
            effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform; communicate deadline to N users.' },
            steps: [
              'Create the IAM policy that denies all actions when no recent MFA is present.',
              'Attach it as a permission boundary (or as a deny policy) to the listed users.',
              'Notify each user with a deadline to enroll MFA in the IAM console.',
              'Revoke each user\'s password after the deadline; surviving users must use Identity Center.',
            ],
            example_code: `resource "aws_iam_policy" "force_mfa" {
  name        = "force-mfa-deny-without-mfa"
  description = "Denies all actions for the principal unless authenticated within the last hour with MFA."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowViewAccountInfo"
        Effect    = "Allow"
        Action    = ["iam:ListVirtualMFADevices","iam:ListMFADevices","iam:ListUsers"]
        Resource  = "*"
      },
      {
        Sid       = "AllowManageOwnMFA"
        Effect    = "Allow"
        Action    = ["iam:ListMFADevices","iam:EnableMFADevice","iam:ResyncMFADevice","iam:DeactivateMFADevice","iam:DeleteVirtualMFADevice","iam:CreateVirtualMFADevice"]
        Resource  = ["arn:aws:iam::*:mfa/$\${aws:username}","arn:aws:iam::*:user/$\${aws:username}"]
      },
      {
        Sid       = "DenyAllExceptListedIfNoMFA"
        Effect    = "Deny"
        NotAction = ["iam:CreateVirtualMFADevice","iam:EnableMFADevice","iam:GetUser","iam:ListMFADevices","iam:ListVirtualMFADevices","iam:ResyncMFADevice","sts:GetSessionToken"]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "force_mfa_each" {
  for_each   = toset(${JSON.stringify(usersWithoutMfa.map((u) => u.UserName))})
  user       = each.value
  policy_arn = aws_iam_policy.force_mfa.arn
}`,
            side_effects: [
              'Affected users will be locked out of everything except MFA management until they enroll a device.',
              'Programmatic access via access keys is also blocked unless a recent MFA presence is included in the session.',
            ],
            prerequisites: [
              'Communicate the deadline to affected users.',
              'Verify each user actually represents a human; for service accounts, prefer IAM roles instead.',
            ],
            references: [
              { title: 'AWS docs: Allow MFA-authenticated IAM users to manage their own MFA', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_self.html' },
            ],
          },
          {
            approach: 'Migrate users to IAM Identity Center (preferred long-term path; aligns with KSI-IAM-AAM).',
            mechanism: 'terraform',
            owner_team: 'Identity / IT',
            cost_impact: { level: 'low', notes: 'IAM Identity Center is free; IdP fees (e.g. Okta SSO) may apply if not already in place.' },
            availability_impact: { level: 'low', notes: 'Brief disruption while users move from old sign-in URL to start portal. CLI users must transition to `aws sso login`.' },
            customer_visible: { level: 'none', notes: 'Internal change only.' },
            effort_estimate: { magnitude: 'weeks', notes: 'Setup is a few days; user migration + permission-set design is the long tail. Use the move to refactor toward least-privilege (overlaps with KSI-IAM-ELP).' },
            steps: [
              'In your IdP (Okta / Azure AD / Google Workspace), create a group for AWS access if you don\'t have one.',
              'Connect the IdP to IAM Identity Center via SAML/OIDC.',
              'Define permission sets corresponding to current IAM user privilege.',
              'Assign the IdP group to the correct AWS account + permission set.',
              'Test with a single user, then notify others to switch to https://<your-portal>.awsapps.com/start.',
              'Delete the IAM user once migrated.',
            ],
            example_code: `resource "aws_ssoadmin_permission_set" "engineering_readonly" {
  name             = "EngineeringReadOnly"
  instance_arn     = data.aws_ssoadmin_instances.this.arns[0]
  session_duration = "PT2H"
}
resource "aws_ssoadmin_managed_policy_attachment" "engineering_readonly" {
  instance_arn       = data.aws_ssoadmin_instances.this.arns[0]
  permission_set_arn = aws_ssoadmin_permission_set.engineering_readonly.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
resource "aws_ssoadmin_account_assignment" "engineering_readonly_prod" {
  instance_arn       = data.aws_ssoadmin_instances.this.arns[0]
  permission_set_arn = aws_ssoadmin_permission_set.engineering_readonly.arn
  principal_id       = data.aws_identitystore_group.engineering.group_id
  principal_type     = "GROUP"
  target_id          = var.prod_account_id
  target_type        = "AWS_ACCOUNT"
}`,
            side_effects: [
              'Users sign in via a different URL.',
              'CLI users must switch to `aws sso login` and named profiles.',
            ],
            references: [
              { title: 'AWS IAM Identity Center', url: 'https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html' },
            ],
          },
          {
            approach: 'Replace IAM users that are actually service accounts with IAM roles (assumed by workloads via IRSA/EC2 instance profile/Lambda execution role).',
            mechanism: 'terraform',
            owner_team: 'SRE',
            cost_impact: { level: 'none', notes: 'No additional charges.' },
            availability_impact: { level: 'medium', notes: 'Requires workload reconfiguration; coordinate maintenance windows. Each migrated workload needs validation.' },
            customer_visible: { level: 'none', notes: 'Internal change.' },
            effort_estimate: { magnitude: 'days', notes: 'Per workload: a few hours to refactor + validate. Total depends on workload count.' },
            steps: [
              'Identify each IAM user that is actually a workload, not a human.',
              'Create an IAM role with the same permissions, trust policy for the consuming compute (EKS pod, EC2 instance, Lambda function).',
              'Update workload configuration to assume the role.',
              'Delete the IAM user and its access keys.',
            ],
            references: [
              { title: 'AWS docs: IAM roles for Amazon EKS', url: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html' },
            ],
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ia-2','ia-2.1','ia-5.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Identity Center migration addresses both account lifecycle automation (AAM) and MFA enforcement.' },
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Service-account-style IAM users should become IAM roles, aligning with SNU.' },
        { ksi_id: 'KSI-IAM-ELP', relationship: 'follows', note: 'During migration, redefine permission sets for least-privilege.' },
      ],
      compliance_blockers: [
        'An external IdP (Okta / Azure AD / Google Workspace) must exist to attach to Identity Center for the migration path.',
      ],
    }),

    // ----- Finding 3: Virtual-MFA-on-privileged disallowed -----
    finding({
      rule: 'aws.iam.no_virtual_mfa_for_console_users',
      passed: usersOnVirtualMfa.length === 0,
      severity: 'high',
      current: {
        summary: usersOnVirtualMfa.length === 0
          ? 'No console-enabled IAM users are using virtual (TOTP) MFA.'
          : `${usersOnVirtualMfa.length} console-enabled IAM user(s) are using virtual (TOTP) MFA, which is NOT phishing-resistant.`,
        observations: {
          virtual_mfa_devices: virtualMfaDevices,
          console_users_on_virtual_mfa: usersOnVirtualMfa.map((u) => ({ UserName: u.UserName, Arn: u.Arn, mfaDevices: u.mfaDevices })),
        },
      },
      target: {
        summary: 'Console-enabled users authenticate with FIDO2/WebAuthn security keys (hardware tokens), not virtual TOTP.',
        rationale: 'FedRAMP 20x KSI-IAM-MFA specifically calls for *phishing-resistant* MFA. TOTP can be intercepted by adversary-in-the-middle phishing; FIDO2/WebAuthn bind the credential to the origin and cannot be phished.',
      },
      gap: usersOnVirtualMfa.length === 0 ? undefined : {
        description: 'Console users with TOTP MFA are not protected against modern phishing techniques (AitM, EvilGinx, etc.).',
        affected_resources: usersOnVirtualMfa.map<AffectedResource>((u) => ({
          type: 'aws_iam_user_mfa_device',
          identifier: u.mfaDevices[0]?.SerialNumber ?? '',
          name: u.UserName,
          attributes: { EnableDate: u.mfaDevices[0]?.EnableDate },
        })),
      },
      remediation: usersOnVirtualMfa.length === 0 ? undefined : {
        summary: 'Replace virtual MFA with FIDO2 security keys for any console-enabled user.',
        options: [
          {
            approach: 'Register a FIDO2 security key for each user; deactivate the virtual MFA.',
            mechanism: 'console',
            owner_team: 'Identity / IT',
            cost_impact: { level: 'low', notes: '~$50-$100 per security key, per user.' },
            availability_impact: { level: 'none', notes: 'Users can keep working with their existing virtual MFA until the new key is registered and tested.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'days', notes: '15 min per user × N users; key distribution logistics may extend timeline.' },
            steps: [
              'Each user, in IAM > Security credentials > MFA: choose Assign MFA device > FIDO security key.',
              'Test sign-in with the new key.',
              'Deactivate the virtual MFA device.',
            ],
            references: [
              { title: 'AWS docs: Enabling a FIDO security key', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_fido.html' },
            ],
          },
          {
            approach: 'Migrate the user to Identity Center where the IdP enforces WebAuthn (preferred — see Finding 2).',
            mechanism: 'process',
            owner_team: 'Identity / IT',
            steps: ['See Finding 2 remediation option "Migrate users to IAM Identity Center".'],
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[0]!],
      nist_controls: ['ia-2.1','ia-2.8'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-APM', relationship: 'shares-remediation', note: 'Phishing-resistant MFA migration is part of the broader passwordless-authentication direction.' },
      ],
    }),

    // ----- Finding 4: SCP deny without MFA -----
    finding({
      rule: 'aws.org.scp_denies_actions_without_mfa',
      passed: scpsWithMfaDeny.length >= 1,
      severity: 'high',
      current: {
        summary: orgReachable
          ? (scpsWithMfaDeny.length >= 1
            ? `${scpsWithMfaDeny.length} SCP(s) deny actions when MFA is absent.`
            : `${allScps.length} SCPs found in the org; none deny actions on absence of MFA.`)
          : 'Organizations API not reachable from this account — SCP scan skipped. This is expected when the collector is run from a member account rather than the management account.',
        observations: {
          orgReachable,
          total_scps: allScps.length,
          scps_with_mfa_deny: scpsWithMfaDeny.map((s) => ({ id: s.id, name: s.name, type: s.type })),
        },
      },
      target: {
        summary: 'An SCP attached to the prod OU (or the root) denies all actions when the calling principal has not recently authenticated with MFA.',
        rationale: 'Org-level guardrails defend against an IAM policy regression in any single account. NIST IA-2(1) and FedRAMP 20x recommend org-wide MFA enforcement at the SCP layer.',
      },
      gap: scpsWithMfaDeny.length >= 1 || !orgReachable ? undefined : {
        description: 'No SCP in the organization denies actions on absence of MultiFactorAuthPresent. A compromised IAM user with old access keys could perform high-impact actions without re-authenticating.',
        affected_resources: [{ type: 'aws_organizations_policy_attachment', identifier: 'org-root', attributes: { existing_scp_count: allScps.length } }],
      },
      remediation: scpsWithMfaDeny.length >= 1 || !orgReachable ? undefined : {
        summary: 'Create an SCP that denies non-trivial actions for principals without recent MFA and attach it to the prod OU.',
        options: [
          {
            approach: 'Apply an org-wide "deny if no MFA" SCP.',
            mechanism: 'terraform',
            owner_team: 'Security',
            cost_impact: { level: 'none', notes: 'AWS Organizations + SCPs are free.' },
            availability_impact: { level: 'medium', notes: 'Mis-scoped SCP can deny legitimate service-linked actions and cause outages. Stage in test OU first.' },
            customer_visible: { level: 'none', notes: 'Internal control plane only.' },
            effort_estimate: { magnitude: 'days', notes: 'Drafting + testing in a non-prod OU; gradual rollout.' },
            example_code: `resource "aws_organizations_policy" "deny_no_mfa" {
  name = "deny-no-mfa"
  type = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyOnNoMFA"
        Effect    = "Deny"
        NotAction = [
          # actions necessary for the principal to obtain MFA-credentialed session
          "iam:GetUser","iam:ListMFADevices","iam:ListVirtualMFADevices",
          "iam:EnableMFADevice","iam:ResyncMFADevice","iam:CreateVirtualMFADevice",
          "iam:DeactivateMFADevice","iam:DeleteVirtualMFADevice",
          "sts:GetSessionToken","sts:GetCallerIdentity"
        ]
        Resource  = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
          # Exempt service-linked roles that authenticate via their own mechanism
          StringNotLike = { "aws:PrincipalArn" = "arn:aws:iam::*:role/aws-service-role/*" }
        }
      }
    ]
  })
}
resource "aws_organizations_policy_attachment" "deny_no_mfa_to_prod_ou" {
  policy_id = aws_organizations_policy.deny_no_mfa.id
  target_id = var.prod_ou_id
}`,
            steps: [
              'Run from the management account (or a delegated administrator).',
              'Stage the SCP in a TEST OU first; confirm no service-linked role disruptions.',
              'Cut over to prod OU.',
              'Validate by trying a CLI call from a non-MFA session — should be denied.',
            ],
            side_effects: [
              'Any process using raw IAM access keys without including a recent MFA session token will start failing.',
              'Some AWS service operations may be authenticated by service-linked roles; the exemption above handles common cases but test carefully.',
            ],
            prerequisites: [
              'AWS Organizations must be enabled with `aws-service-access` for `iam.amazonaws.com`.',
              `Run from the management account or a delegated admin (current account: ${ctx.account} — collector noted ${orgReachable ? 'reachable' : 'NOT reachable'} from here).`,
            ],
            references: [
              { title: 'AWS docs: SCP examples — Require MFA', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html' },
            ],
          },
        ],
      },
      alternative_satisfiers: [altSatisfiers[1]!],
      nist_controls: ['ac-2.1','ia-2.1','ia-2.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-DFP', relationship: 'shares-remediation', note: 'SCP rollout for MFA enforcement aligns with the broader CNA-DFP guardrail strategy.' },
      ],
      compliance_blockers: orgReachable ? [] : [
        'AWS Organizations must be enabled with this account as the management account (or delegated admin for IAM).',
        'Trusted access for `iam.amazonaws.com` must be granted at the org level.',
      ],
    }),
  ];

  // ---- 3rd-party tool detection ----
  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    iam_saml_provider_arns: samlProviders,
    iam_oidc_provider_urls: oidcProviders,
    iam_user_names: userRecords.map((u) => u.UserName),
    iam_role_names: [], // populated by IAM-AAM/IAM-SNU collectors; left empty here to avoid duplicate API calls
    identity_center_present: identityCenterPresent,
  });

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-IAM-SNU — Securing Non-User Authentication
// =====================================================================
export async function collectIamSnu(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // Total access keys across all users
  let accessKeyCount = 0;
  const users = await listAllIamUsers(ctx);
  for (const u of users) {
    if (!u.UserName) continue;
    try {
      const ak = await iamClient.send(new ListAccessKeysCommand({ UserName: u.UserName }));
      accessKeyCount += ak.AccessKeyMetadata?.length ?? 0;
    } catch (e: any) {
      warnings.push(`ListAccessKeys ${u.UserName}: ${e.message}`);
    }
  }
  evidence.push(ev('iam.access_key_total', { count: accessKeyCount }));

  // Role inventory — short-lived role-based access is the preferred mechanism
  let roleCount = 0;
  try {
    let marker: string | undefined;
    do {
      const out = await iamClient.send(new ListRolesCommand({ Marker: marker, MaxItems: 100 }));
      roleCount += out.Roles?.length ?? 0;
      { const _nm = out.IsTruncated ? out.Marker : undefined; marker = _nm === marker ? undefined : _nm; }
    } while (marker);
    evidence.push(ev('iam.role_count', { count: roleCount }));
  } catch (e: any) {
    warnings.push(`ListRoles: ${e.message}`);
  }

  // OIDC providers used for workload identity (GitHub Actions, GitLab, etc.)
  let oidcProviders: string[] = [];
  try {
    const o = await iamClient.send(new ListOpenIDConnectProvidersCommand({}));
    oidcProviders = (o.OpenIDConnectProviderList ?? []).map((p) => p.Arn ?? '').filter(Boolean);
    evidence.push(ev('iam.ListOpenIDConnectProviders', oidcProviders));
  } catch (e: any) {
    warnings.push(`ListOpenIDConnectProviders: ${e.message}`);
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'HashiCorp Vault or other secret broker',
      description: 'Workloads obtain short-lived AWS credentials from Vault, eliminating static access keys.',
      evidence_required: ['Vault config showing AWS secret engine bound to short TTL', 'Sample audit log entry showing dynamic credential issuance'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.iam.access_keys_minimal',
      passed: accessKeyCount <= 5,
      severity: 'high',
      current: {
        summary: accessKeyCount === 0
          ? 'No IAM access keys exist — all access is role-based.'
          : `${accessKeyCount} IAM access key(s) exist across ${users.length} user(s).`,
        observations: { access_key_count: accessKeyCount, iam_user_count: users.length, role_count: roleCount },
      },
      target: { summary: '≤ 5 access keys total (or 0 — ideal). Workloads use roles + STS, not access keys.', rationale: 'Long-lived access keys are the #1 cloud credential breach source. NIST IA-5(1), IA-9.' },
      gap: accessKeyCount <= 5 ? undefined : {
        description: 'Too many long-lived credentials in the org. Each is a potential leak point.',
        affected_resources: [{ type: 'aws_iam_access_key', identifier: 'aggregate', attributes: { total_count: accessKeyCount } }],
      },
      remediation: accessKeyCount <= 5 ? undefined : {
        summary: 'Replace each access key with role-based authentication. Cross-references KSI-IAM-AAM Finding 3 + KSI-IAM-MFA Finding 2.',
        options: [
          {
            approach: 'For EKS workloads: IRSA (IAM Roles for Service Accounts).',
            mechanism: 'terraform',
            owner_team: 'SRE',
            cost_impact: { level: 'none', notes: 'Free.' },
            availability_impact: { level: 'medium', notes: 'Per-workload migration.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'days', notes: 'Per workload.' },
            steps: [
              'Enable the OIDC provider on the EKS cluster.',
              'Create an IAM role with a trust policy for the K8s service account.',
              'Annotate the K8s SA with the role ARN.',
              'Update workload to use the SA.',
              'Delete the access key.',
            ],
            references: [{ title: 'IRSA', url: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html' }],
          },
          {
            approach: 'For CI/CD: GitHub Actions OIDC federation (no static access keys).',
            mechanism: 'terraform',
            owner_team: 'SRE',
            cost_impact: { level: 'none', notes: 'Free.' },
            availability_impact: { level: 'low', notes: 'Per-pipeline migration.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'days', notes: 'Per repo / pipeline.' },
            steps: [
              'Create an IAM OIDC provider for token.actions.githubusercontent.com.',
              'Create an IAM role trusted by that OIDC provider with sub claim conditions.',
              'Update GitHub Actions workflow to use aws-actions/configure-aws-credentials with role-to-assume.',
              'Remove the AWS access key from GitHub Secrets.',
            ],
            example_code: `resource "aws_iam_openid_connect_provider" "gha" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}
resource "aws_iam_role" "gha_deploy" {
  name = "gha-deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.gha.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:your-org/your-repo:ref:refs/heads/main"
        }
      }
    }]
  })
}`,
            references: [{ title: 'GitHub OIDC + AWS', url: 'https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services' }],
          },
          {
            approach: 'For on-premises / off-cloud workloads: IAM Roles Anywhere.',
            mechanism: 'terraform',
            owner_team: 'SRE',
            cost_impact: { level: 'low', notes: 'Roles Anywhere has low per-trust-anchor + per-session costs.' },
            availability_impact: { level: 'medium', notes: 'Per-workload migration; requires PKI.' },
            customer_visible: { level: 'none', notes: 'Internal.' },
            effort_estimate: { magnitude: 'weeks', notes: 'Standing up PKI + per-workload integration.' },
            steps: [
              'Establish a CA (ACM PCA or external).',
              'Create a Roles Anywhere trust anchor referencing the CA.',
              'Create a Roles Anywhere profile + role.',
              'Distribute end-entity certs to workloads.',
              'Workloads use aws_signing_helper to obtain STS credentials.',
            ],
            references: [{ title: 'IAM Roles Anywhere', url: 'https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html' }],
          },
        ],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ac-2.7','ia-5','ia-9'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-AAM', relationship: 'shares-remediation', note: 'Same migration effort as AAM.' },
        { ksi_id: 'KSI-SVC-ASM', relationship: 'shares-remediation', note: 'Eliminates static secrets that ASM would otherwise have to rotate.' },
      ],
    }),

    finding({
      rule: 'aws.iam.oidc_providers_configured',
      passed: oidcProviders.length >= 1,
      severity: 'info',
      current: {
        summary: oidcProviders.length >= 1
          ? `${oidcProviders.length} OIDC provider(s) registered (typically GitHub Actions, GitLab, EKS).`
          : 'No OIDC providers registered. Workload federation is not in use (unless via SAML).',
        observations: { oidc_provider_arns: oidcProviders },
      },
      target: { summary: 'OIDC federation in use for at least one workload type (CI/CD, EKS, off-cloud).', rationale: 'OIDC federation eliminates static credentials for workloads.' },
      gap: oidcProviders.length >= 1 ? undefined : {
        description: 'Without OIDC, workloads likely use static access keys (covered by Finding 1).',
        affected_resources: [{ type: 'aws_iam_openid_connect_provider', identifier: 'none', attributes: {} }],
      },
      remediation: oidcProviders.length >= 1 ? undefined : {
        summary: 'Register an OIDC provider for your main workload identity source.',
        options: [{
          approach: 'Register GitHub Actions OIDC provider (common starting point).',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Net-new; existing access paths continue.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['See Finding 1 GitHub OIDC remediation steps.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-9'],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    iam_oidc_provider_urls: oidcProviders,
  });

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
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
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // GuardDuty enabled?
  let detectorEnabled = false;
  let detectorId: string | undefined;
  try {
    const gd = aws.guardduty(ctx.auth);
    const lst = await gd.send(new ListDetectorsCommand({}));
    detectorId = lst.DetectorIds?.[0];
    if (detectorId) {
      const d = await gd.send(new GetDetectorCommand({ DetectorId: detectorId }));
      detectorEnabled = d.Status === 'ENABLED';
      evidence.push(ev('guardduty.GetDetector', { detectorId, status: d.Status, findingPublishingFrequency: d.FindingPublishingFrequency }));
    }
  } catch (e: any) {
    warnings.push(`GuardDuty: ${e.message}`);
  }

  // EventBridge rules consuming GuardDuty findings
  let gdRulesWithTargets = 0;
  try {
    const eb = aws.eventbridge(ctx.auth);
    let tok: string | undefined;
    const matching: Array<{ name: string; targets: number }> = [];
    do {
      const rl = await eb.send(new ListRulesCommand({ NextToken: tok, Limit: 100 }));
      for (const r of rl.Rules ?? []) {
        // EventPattern is a string; look for "aws.guardduty" event source
        if (r.EventPattern && /"aws\.guardduty"/.test(r.EventPattern)) {
          if (!r.Name) continue;
          const t = await eb.send(new ListTargetsByRuleCommand({ Rule: r.Name }));
          const count = t.Targets?.length ?? 0;
          if (count > 0) gdRulesWithTargets++;
          matching.push({ name: r.Name, targets: count });
        }
      }
      tok = rl.NextToken;
    } while (tok);
    evidence.push(ev('eventbridge.guardduty_rules', matching));
  } catch (e: any) {
    warnings.push(`EventBridge rules: ${e.message}`);
  }

  // Recent GuardDuty findings count (informational)
  let recentFindings = 0;
  if (detectorId) {
    try {
      const gd = aws.guardduty(ctx.auth);
      const f = await gd.send(new GdListFindingsCommand({ DetectorId: detectorId, MaxResults: 50 }));
      recentFindings = f.FindingIds?.length ?? 0;
      evidence.push(ev('guardduty.recent_finding_count', recentFindings));
    } catch (e: any) {
      warnings.push(`GuardDuty findings: ${e.message}`);
    }
  }

  // Security Hub critical IAM findings (informational)
  let shCriticalIamCount = 0;
  try {
    const sh = aws.securityhub(ctx.auth);
    const f = await sh.send(new ShGetFindingsCommand({
      Filters: {
        SeverityLabel: [{ Value: 'CRITICAL', Comparison: 'EQUALS' }],
        Type: [{ Value: 'Software and Configuration Checks/AWS Security Best Practices/IAM', Comparison: 'PREFIX' }],
        WorkflowStatus: [{ Value: 'NEW', Comparison: 'EQUALS' }, { Value: 'NOTIFIED', Comparison: 'EQUALS' }],
      },
      MaxResults: 100,
    }));
    shCriticalIamCount = f.Findings?.length ?? 0;
    evidence.push(ev('securityhub.critical_iam_findings', { count: shCriticalIamCount }));
  } catch (e: any) {
    warnings.push(`Security Hub: ${e.message}`);
  }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party SOAR / SIEM with auto-response (Tines, Torq, Splunk SOAR, Datadog Workflow Automation)',
      description: 'Response automation may be driven by an external SOAR consuming AWS audit logs / GuardDuty findings.',
      evidence_required: ['SOAR playbook export for IAM credential-compromise', 'Sample execution log', 'Integration with AWS (GuardDuty Findings → SOAR queue)'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.guardduty.enabled',
      passed: detectorEnabled,
      severity: 'critical',
      current: {
        summary: detectorEnabled
          ? `GuardDuty is enabled (detector ${detectorId}).`
          : 'GuardDuty is NOT enabled.',
        observations: { detectorEnabled, detectorId },
      },
      target: { summary: 'GuardDuty enabled org-wide with 15-min finding-publishing frequency.', rationale: 'GuardDuty is AWS\'s threat-detection service. NIST SI-4 (system monitoring).' },
      gap: detectorEnabled ? undefined : {
        description: 'Without GuardDuty, IAM credential compromise + anomalous API patterns go undetected.',
        affected_resources: [{ type: 'aws_guardduty_detector', identifier: ctx.account ?? '', attributes: {} }],
      },
      remediation: detectorEnabled ? undefined : {
        summary: 'Enable GuardDuty via Terraform; enable org-wide via delegated admin.',
        options: [{
          approach: 'Enable GuardDuty + delegate to security-tooling account.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'GuardDuty is billed per analyzed CloudTrail event, VPC flow log, DNS query. For a SaaS CSP, expect $hundreds-thousands/month per account depending on usage.' },
          availability_impact: { level: 'none', notes: 'No availability impact — pure detection.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Org-wide enablement + delegated admin setup.' },
          steps: [
            'Enable GuardDuty in the management account.',
            'Designate a delegated administrator (the security tooling account).',
            'From the delegated admin, auto-enable for all current + new accounts.',
            'Configure SNS / EventBridge for finding delivery.',
          ],
          example_code: `resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}`,
          references: [{ title: 'GuardDuty', url: 'https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['si-4','si-4.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-OSM', relationship: 'precedes', note: 'GuardDuty findings are a primary SIEM input.' },
      ],
    }),

    finding({
      rule: 'aws.guardduty.has_eventbridge_response',
      passed: gdRulesWithTargets >= 1,
      severity: 'high',
      current: {
        summary: gdRulesWithTargets >= 1
          ? `${gdRulesWithTargets} EventBridge rule(s) consume GuardDuty findings.`
          : 'No EventBridge rule routes GuardDuty findings to a response target — detection without automated response.',
        observations: { gdRulesWithTargets },
      },
      target: { summary: 'At least one EventBridge rule routes IAM-credential-compromise findings (e.g. UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS) to a response Lambda or SNS.', rationale: 'KSI-IAM-SUS requires AUTOMATIC disable/secure. Detection without automation is insufficient.' },
      gap: gdRulesWithTargets >= 1 ? undefined : {
        description: 'GuardDuty surfaces findings but nothing acts on them automatically — a human must triage every alert.',
        affected_resources: [{ type: 'aws_cloudwatch_event_rule', identifier: 'none-for-guardduty', attributes: {} }],
      },
      remediation: gdRulesWithTargets >= 1 ? undefined : {
        summary: 'Build EventBridge → Lambda automation that disables IAM principals on credential-compromise findings.',
        options: [{
          approach: 'EventBridge rule + Lambda for IAM credential compromise response.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'EventBridge + Lambda invocations are negligible at finding volumes.' },
          availability_impact: { level: 'medium', notes: 'Auto-disable can cause outages on false positives. Pilot with notify-only first, then move to auto-disable for high-confidence finding types.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Write + test response Lambda; pilot in non-prod.' },
          steps: [
            'Define an EventBridge rule matching GuardDuty CredentialAccess + UnauthorizedAccess finding types.',
            'Write a Lambda that: (a) extracts the affected principal, (b) deactivates IAM access keys via UpdateAccessKey, (c) attaches a Deny-everything policy, (d) posts to PagerDuty/Slack.',
            'Start in notify-only mode for 2-4 weeks; tune false positives.',
            'Promote to auto-disable for high-confidence finding types.',
          ],
          example_code: `resource "aws_cloudwatch_event_rule" "guardduty_iam_response" {
  name = "guardduty-iam-credential-compromise"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/" },
        { prefix = "CredentialAccess:IAMUser/" },
        { prefix = "Stealth:IAMUser/" }
      ]
    }
  })
}
resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.guardduty_iam_response.name
  arn  = aws_lambda_function.iam_disable_responder.arn
}`,
          references: [{ title: 'GuardDuty + EventBridge', url: 'https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ir-4','ir-4.1','au-6'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-INR-RIR', relationship: 'shares-remediation', note: 'Same alert-routing infrastructure satisfies IR procedure plumbing.' },
      ],
    }),

    finding({
      rule: 'aws.security_hub.no_critical_iam_findings_open',
      passed: shCriticalIamCount === 0,
      severity: 'high',
      current: {
        summary: shCriticalIamCount === 0
          ? 'No open CRITICAL IAM findings in Security Hub.'
          : `${shCriticalIamCount} open CRITICAL IAM finding(s) in Security Hub.`,
        observations: { shCriticalIamCount },
      },
      target: { summary: 'Zero open CRITICAL IAM findings (NEW or NOTIFIED). Resolved or SUPPRESSED with documented justification.', rationale: 'NIST SI-4, IR-4. Critical findings represent active exposures.' },
      gap: shCriticalIamCount === 0 ? undefined : {
        description: 'Open critical findings are unaddressed exposures.',
        affected_resources: [{ type: 'aws_securityhub_finding', identifier: 'aggregate', attributes: { count: shCriticalIamCount } }],
      },
      remediation: shCriticalIamCount === 0 ? undefined : {
        summary: 'Triage each finding via the Security Hub console.',
        options: [{
          approach: 'Open Security Hub Findings filtered to CRITICAL + IAM + NEW.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Depends on the remediation per finding.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-finding triage.' },
          steps: ['Open Security Hub Findings.', 'Filter CRITICAL + Type=IAM + WorkflowStatus=NEW.', 'Triage each: resolve, suppress with reason, or mark notified.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-4','ca-7'],
    }),
  ];

  const thirdParty: ThirdPartyToolMatch[] = detectThirdParty({
    eventbridge_rule_targets: [], // could populate from ListTargetsByRule, but adds API calls — keep minimal here
  });
  // Detect SOAR via EventBridge target patterns
  const soarToolDetected = thirdParty.some((t) => /Tines|Torq/.test(t.name));
  if (soarToolDetected) {
    altSatisfiers[0]!.detected = true;
    altSatisfiers[0]!.detection_signals = thirdParty.filter((t) => /Tines|Torq/.test(t.name)).flatMap((t) => t.detection_signals);
  }

  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence,
    findings,
    warnings,
    ksi_level_alternatives: altSatisfiers,
    third_party_tools_detected: thirdParty,
  };
}

// =====================================================================
// KSI-CNA-DFP — Defining Functionality and Privileges
// Lives in iam.ts because the bulk of evidence is IAM-policy hygiene.
// =====================================================================
export async function collectCnaDfp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const iamClient = aws.iam(ctx.auth);

  // ---- IAM customer-managed policies with wildcards (re-used pattern from ELP) ----
  const wildcardPolicies: Array<{ policyArn: string; statementIdx: number }> = [];
  let policyCount = 0;
  try {
    let marker: string | undefined;
    do {
      const out = await iamClient.send(new ListPoliciesCommand({ Scope: 'Local', Marker: marker, MaxItems: 100 }));
      for (const p of out.Policies ?? []) {
        if (!p.Arn || !p.DefaultVersionId) continue;
        policyCount++;
        try {
          const v = await iamClient.send(new GetPolicyVersionCommand({ PolicyArn: p.Arn, VersionId: p.DefaultVersionId }));
          // GetPolicyVersion returns the doc URL-encoded; defensive parse so a
          // malformed/truncated policy doesn't crash the whole collector.
          let doc: any = { Statement: [] };
          try {
            const decoded = decodeURIComponent(v.PolicyVersion?.Document ?? '{}');
            doc = JSON.parse(decoded);
          } catch (parseErr: any) {
            warnings.push(`GetPolicyVersion ${p.Arn}: malformed policy JSON: ${parseErr.message}`);
            continue;
          }
          const stmts: any[] = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement].filter(Boolean);
          stmts.forEach((s, i) => {
            const allow = s.Effect === 'Allow';
            const allActions = s.Action === '*' || (Array.isArray(s.Action) && s.Action.includes('*'));
            const allResources = s.Resource === '*' || (Array.isArray(s.Resource) && s.Resource.includes('*'));
            if (allow && allActions && allResources && !s.Condition) {
              wildcardPolicies.push({ policyArn: p.Arn!, statementIdx: i });
            }
          });
        } catch { /* ignore */ }
      }
      { const _nm = out.IsTruncated ? out.Marker : undefined; marker = _nm === marker ? undefined : _nm; }
    } while (marker);
  } catch (e: any) { warnings.push(`ListPolicies: ${e.message}`); }
  evidence.push(ev('iam.policy_wildcard_scan', { policy_count: policyCount, wildcards: wildcardPolicies }));

  // ---- SCPs attached to org / OUs ----
  const scpsTotal: any[] = [];
  let orgReachable = true;
  try {
    const org = aws.organizations(ctx.auth);
    let tok: string | undefined;
    do {
      const ps = await org.send(new OrgListPoliciesCommand({ Filter: 'SERVICE_CONTROL_POLICY', NextToken: tok }));
      for (const p of ps.Policies ?? []) {
        scpsTotal.push({ id: p.Id, name: p.Name, type: p.Type, awsManaged: p.AwsManaged });
      }
      tok = ps.NextToken;
    } while (tok);
    evidence.push(ev('organizations.scp_count', { total: scpsTotal.length, customer_managed: scpsTotal.filter((s) => !s.awsManaged).length }));
  } catch (e: any) {
    orgReachable = false;
    warnings.push(`Organizations not reachable: ${e.message}`);
  }

  // ---- Access Analyzer external-access findings ----
  let externalAccessFindings = 0;
  try {
    const aa = aws.accessanalyzer(ctx.auth);
    const an = await aa.send(new ListAnalyzersCommand({ type: 'ACCOUNT' }));
    for (const analyzer of an.analyzers ?? []) {
      let t: string | undefined;
      do {
        const f = await aa.send(new AaListFindingsCommand({
          analyzerArn: analyzer.arn,
          filter: { status: { eq: ['ACTIVE'] } },
          nextToken: t,
          maxResults: 100,
        }));
        externalAccessFindings += f.findings?.length ?? 0;
        t = f.nextToken;
      } while (t);
    }
    evidence.push(ev('accessanalyzer.external_access_findings', { count: externalAccessFindings }));
  } catch (e: any) { warnings.push(`Access Analyzer: ${e.message}`); }

  const customerScps = scpsTotal.filter((s) => !s.awsManaged);

  const findings = [
    finding({
      rule: 'aws.iam.no_unconditional_admin_wildcards',
      passed: wildcardPolicies.length === 0,
      severity: 'critical',
      current: {
        summary: wildcardPolicies.length === 0
          ? `No customer-managed policy grants unconditional admin across ${policyCount} policies.`
          : `${wildcardPolicies.length} statement(s) grant unconditional Action:*/Resource:*/Allow.`,
        observations: { policy_count: policyCount, wildcards: wildcardPolicies },
      },
      target: { summary: 'Zero customer-managed policies with unconditional admin.', rationale: 'NIST AC-6 / CM-7. Unconditional admin makes the rest of IAM hygiene moot.' },
      gap: wildcardPolicies.length === 0 ? undefined : {
        description: 'Each wildcard is effectively root-equivalent.',
        affected_resources: wildcardPolicies.map<AffectedResource>((w) => ({
          type: 'aws_iam_policy', identifier: w.policyArn, name: w.policyArn.split('/').pop() ?? w.policyArn,
          attributes: { statement_index: w.statementIdx },
        })),
      },
      remediation: wildcardPolicies.length === 0 ? undefined : {
        summary: 'Replace each wildcard with scoped Action + Resource lists.',
        options: [{
          approach: 'See KSI-IAM-ELP Finding 1 — same remediation path.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Risk of denying legitimate access if scoped too tight.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per policy.' },
          steps: ['Use Access Advisor to inform scope.', 'Draft scoped policy.', 'Roll out alongside wildcard.', 'Remove wildcard.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','cm-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Identical scan.' },
      ],
    }),

    finding({
      rule: 'aws.org.customer_scps_present',
      passed: customerScps.length >= 1,
      severity: 'high',
      current: {
        summary: orgReachable
          ? (customerScps.length >= 1
            ? `${customerScps.length} customer-managed SCP(s) present (org-wide guardrails active).`
            : `${scpsTotal.length} SCP(s) total; 0 customer-managed. Only AWS-default SCPs are attached — minimal protection.`)
          : 'Organizations API not reachable from this account.',
        observations: { orgReachable, total_scps: scpsTotal.length, customer_managed_scps: customerScps.length },
      },
      target: { summary: 'At least one customer-managed SCP attached to the org or prod OU enforces guardrails (deny region, deny root, require MFA, deny CloudTrail-disable, etc.).', rationale: 'NIST CM-7. SCPs are org-wide privilege guardrails; without them, a single account compromise has no org-level safety net.' },
      gap: (customerScps.length >= 1 || !orgReachable) ? undefined : {
        description: 'No org-level guardrails defending against account-level mistakes.',
        affected_resources: [{ type: 'aws_organizations_policy', identifier: 'none-customer-managed', attributes: { total_scps: scpsTotal.length } }],
      },
      remediation: (customerScps.length >= 1 || !orgReachable) ? undefined : {
        summary: 'Deploy a baseline SCP set: deny disable-CloudTrail, deny disable-GuardDuty, deny non-approved regions, deny root usage.',
        options: [{
          approach: 'Deploy baseline SCPs via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'SCPs are free.' },
          availability_impact: { level: 'medium', notes: 'Mis-scoped SCPs can disrupt prod. Stage in test OU first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'SCP design + canary + rollout.' },
          steps: ['Inventory current account behaviors.', 'Author baseline SCPs.', 'Attach to test OU; monitor for false positives.', 'Roll out to prod OU.'],
          example_code: `resource "aws_organizations_policy" "deny_disable_cloudtrail" {
  name = "deny-disable-cloudtrail"
  type = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Deny"
      Action = ["cloudtrail:StopLogging","cloudtrail:DeleteTrail","cloudtrail:UpdateTrail"]
      Resource = "*"
    }]
  })
}`,
          references: [{ title: 'SCP examples', url: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','cm-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-MFA', relationship: 'shares-remediation', note: 'MFA-deny SCP is part of the baseline.' },
        { ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Deny-disable-CloudTrail SCP is also a logging-protection control.' },
      ],
      compliance_blockers: orgReachable ? [] : ['Must be run from the Organizations management account or a delegated admin.'],
    }),

    finding({
      rule: 'aws.access_analyzer.no_external_access_findings',
      passed: externalAccessFindings === 0,
      severity: 'high',
      current: {
        summary: externalAccessFindings === 0
          ? 'No active external-access findings from IAM Access Analyzer.'
          : `${externalAccessFindings} active external-access finding(s) from Access Analyzer.`,
        observations: { count: externalAccessFindings },
      },
      target: { summary: 'Zero unresolved external-access findings, OR each is documented (intentional cross-account access).', rationale: 'NIST AC-3, AC-4. External access from outside the org / trusted zone needs scrutiny.' },
      gap: externalAccessFindings === 0 ? undefined : {
        description: 'Each finding represents a resource grant to a principal outside the org / trusted zone.',
        affected_resources: [{ type: 'aws_accessanalyzer_finding', identifier: 'aggregate', attributes: { count: externalAccessFindings } }],
      },
      remediation: externalAccessFindings === 0 ? undefined : {
        summary: 'Triage each finding in the Access Analyzer console — resolve or archive with justification.',
        options: [{
          approach: 'Triage active findings via console + IaC fixes.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Removing legitimate access could break integrations; verify each.' },
          customer_visible: { level: 'low', notes: 'May affect cross-account partner access.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-finding triage.' },
          steps: ['Open Access Analyzer console.', 'For each finding, decide: resolve (remove grant) or archive (document intent).', 'Apply IaC change if resolving.'],
          references: [{ title: 'IAM Access Analyzer', url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','ac-4','ac-6'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return {
    provider: 'aws',
    account_id: ctx.account,
    region_set: [ctx.region],
    evidence, findings, warnings,
    third_party_tools_detected: thirdParty,
  };
}

// ---- CSV helper for IAM credential report ----
function parseCsv(s: string): any[] {
  const lines = s.trim().split('\n');
  if (lines.length < 2) return [];
  const headers = lines[0]!.split(',');
  return lines.slice(1).map((line) => {
    const cells = line.split(',');
    const row: any = {};
    headers.forEach((h, i) => { row[h] = cells[i] ?? ''; });
    return row;
  });
}
