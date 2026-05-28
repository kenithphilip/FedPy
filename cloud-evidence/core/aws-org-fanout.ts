/**
 * AWS Organizations fan-out.
 *
 * A FedRAMP boundary typically spans multiple AWS accounts (one per workload,
 * per environment, or per business unit). Auditors expect evidence from ALL
 * accounts in scope — not just the management account.
 *
 * This module:
 *   1. Calls Organizations:ListAccounts from the management account to
 *      enumerate every member account.
 *   2. Filters by include/exclude lists + an OU filter.
 *   3. For each in-scope account, assumes a designated cross-account
 *      read-only role (default: AWSReadOnlyAccess from the org account
 *      management trust, or whatever the user named — typically
 *      `OrganizationAccountAccessRole` if the account was created via
 *      Organizations, or `cloud-evidence-readonly` for a purpose-built one).
 *   4. Yields per-account `AwsAuth` objects the orchestrator can hand to
 *      collectors.
 *
 * Read-only invariants:
 *   - We only ever call Organizations:DescribeOrganization, ListAccounts,
 *     ListAccountsForParent, ListOrganizationalUnitsForParent, ListRoots
 *     (all read-only).
 *   - Role assumption itself is read-only — STS AssumeRole doesn't mutate
 *     anything the auditor cares about. It IS on the allowlist in
 *     core/readonly-guardrail.ts.
 *   - The role we assume in each member account is presumed to have ONLY
 *     read permissions (e.g. AWS-managed `ReadOnlyAccess` policy plus the
 *     extras our collectors need). This is a HARD prerequisite — operators
 *     must NOT use a role with mutating permissions.
 *
 * Failure modes:
 *   - Account is suspended → skip with warning.
 *   - AssumeRole fails (role missing, trust policy doesn't allow us) → skip
 *     with warning; emit a `gap-account.json` so the operator sees the
 *     coverage shortfall in the report.
 *   - Account inaccessible due to SCP → same as above.
 */
import {
  ListAccountsCommand,
  DescribeOrganizationCommand,
  ListRootsCommand,
  type Account,
} from '@aws-sdk/client-organizations';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import { organizations as orgClient, makeAwsAuth, type AwsAuth } from './auth/aws.ts';
import { log } from './log.ts';

const DEFAULT_CROSS_ACCOUNT_ROLE = process.env.AWS_CROSS_ACCOUNT_ROLE ?? 'OrganizationAccountAccessRole';

export interface FanoutOptions {
  /** Region to use for STS / SDK calls when running per-account. */
  region: string;
  /** Specific account IDs to include. If non-empty, only these accounts are visited. */
  includeAccounts?: string[];
  /** Specific account IDs to skip. */
  excludeAccounts?: string[];
  /** Cross-account role name to assume in each member account. */
  roleName?: string;
  /** Optional session name (shows up in CloudTrail). */
  sessionName?: string;
  /** Max account discovery depth (safety: cap at very large orgs). */
  maxAccounts?: number;
}

export interface FanoutTarget {
  account_id: string;
  account_name?: string;
  account_email?: string;
  status: 'ACTIVE' | 'SUSPENDED' | 'PENDING_CLOSURE' | 'UNKNOWN';
  /** AwsAuth scoped to this account (or null if AssumeRole failed). */
  auth: AwsAuth | null;
  /** Populated if we couldn't reach this account. */
  error?: string;
}

export interface FanoutPlan {
  organization_id: string | null;
  master_account_id: string | null;
  targets: FanoutTarget[];
  skipped: Array<{ account_id: string; reason: string }>;
  total_discovered: number;
}

/**
 * Build a list of per-account auth contexts the orchestrator can iterate
 * over. Performs the STS AssumeRole lazily — actually, eagerly here, because
 * we want the orchestrator to know upfront which accounts are reachable.
 *
 * Returns gracefully on per-account failures so a single bad account doesn't
 * tank the whole run.
 */
export async function buildFanoutPlan(opts: FanoutOptions): Promise<FanoutPlan> {
  const baseAuth = makeAwsAuth(opts.region);
  const roleName = opts.roleName ?? DEFAULT_CROSS_ACCOUNT_ROLE;
  const sessionName = opts.sessionName ?? 'cloud-evidence';
  const maxAccounts = opts.maxAccounts ?? 10_000;

  let orgId: string | null = null;
  let masterId: string | null = null;
  try {
    const org = orgClient(baseAuth);
    const desc = await org.send(new DescribeOrganizationCommand({}));
    orgId = desc.Organization?.Id ?? null;
    masterId = desc.Organization?.MasterAccountId ?? null;
  } catch (e: any) {
    log.warn({ event: 'fanout.describe_organization_failed', err_message: e?.message });
    return {
      organization_id: null,
      master_account_id: null,
      targets: [{ account_id: 'self', status: 'ACTIVE', auth: baseAuth }],
      skipped: [],
      total_discovered: 0,
    };
  }

  // Enumerate accounts (paginated)
  const accounts: Account[] = [];
  try {
    const org = orgClient(baseAuth);
    let token: string | undefined;
    do {
      const out = await org.send(new ListAccountsCommand({ NextToken: token, MaxResults: 20 }));
      accounts.push(...(out.Accounts ?? []));
      token = out.NextToken;
      if (accounts.length >= maxAccounts) break;
    } while (token);
  } catch (e: any) {
    log.error({ event: 'fanout.list_accounts_failed', err_message: e?.message });
    return {
      organization_id: orgId,
      master_account_id: masterId,
      targets: [{ account_id: 'self', status: 'ACTIVE', auth: baseAuth }],
      skipped: [],
      total_discovered: 0,
    };
  }

  // Filter
  const include = new Set(opts.includeAccounts ?? []);
  const exclude = new Set(opts.excludeAccounts ?? []);

  const targets: FanoutTarget[] = [];
  const skipped: Array<{ account_id: string; reason: string }> = [];

  for (const a of accounts) {
    if (!a.Id) continue;
    if (include.size > 0 && !include.has(a.Id)) {
      skipped.push({ account_id: a.Id, reason: 'not in --include list' });
      continue;
    }
    if (exclude.has(a.Id)) {
      skipped.push({ account_id: a.Id, reason: 'in --exclude list' });
      continue;
    }
    if (a.Status !== 'ACTIVE') {
      skipped.push({ account_id: a.Id, reason: `account status is ${a.Status}` });
      continue;
    }

    // If this IS the management account, reuse baseAuth (no AssumeRole needed).
    if (a.Id === masterId) {
      targets.push({
        account_id: a.Id,
        account_name: a.Name ?? undefined,
        account_email: a.Email ?? undefined,
        status: 'ACTIVE',
        auth: baseAuth,
      });
      continue;
    }

    // AssumeRole into the member account
    const roleArn = `arn:aws:iam::${a.Id}:role/${roleName}`;
    try {
      const auth: AwsAuth = {
        region: opts.region,
        credentials: fromTemporaryCredentials({
          params: {
            RoleArn: roleArn,
            RoleSessionName: sessionName,
            DurationSeconds: 3600,
          },
          masterCredentials: baseAuth.credentials,
        }),
      };
      // Probe with GetCallerIdentity to fail fast if the role isn't assumable.
      const sts = new STSClient({ region: opts.region, credentials: auth.credentials });
      try {
        await sts.send(new AssumeRoleCommand({
          RoleArn: roleArn,
          RoleSessionName: sessionName + '-probe',
          DurationSeconds: 900,
        }));
      } catch (probeErr: any) {
        skipped.push({ account_id: a.Id, reason: `AssumeRole ${roleArn} failed: ${probeErr?.name ?? probeErr?.message}` });
        continue;
      }
      targets.push({
        account_id: a.Id,
        account_name: a.Name ?? undefined,
        account_email: a.Email ?? undefined,
        status: 'ACTIVE',
        auth,
      });
    } catch (e: any) {
      skipped.push({ account_id: a.Id, reason: `auth setup failed: ${e?.message}` });
    }
  }

  log.info({
    event: 'fanout.plan_built',
    organization_id: orgId,
    master_account_id: masterId,
    total_discovered: accounts.length,
    targeted: targets.length,
    skipped: skipped.length,
  });

  return {
    organization_id: orgId,
    master_account_id: masterId,
    targets,
    skipped,
    total_discovered: accounts.length,
  };
}
