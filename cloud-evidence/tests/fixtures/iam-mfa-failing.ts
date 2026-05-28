/**
 * IAM-MFA test fixture: an environment with multiple failures.
 *   - Root MFA disabled
 *   - One console-enabled user (bob.contractor) without MFA
 *   - alice.smith has MFA + console
 *   - No SCP enforcing MFA
 *   - Virtual MFA in use
 *
 * Per-user responses (ListMFADevices, GetLoginProfile, GetUser, etc.) are
 * encoded as functions of the command input so the same op returns
 * different data depending on which user is being queried.
 */
import type { FakeResponses } from '../helpers/fake-aws-sdk.ts';

class NoSuchEntityException extends Error {
  name = 'NoSuchEntityException';
  constructor(msg = 'NoSuchEntity') { super(msg); }
}

export const iamMfaFailing: FakeResponses = {
  GetAccountSummary: {
    SummaryMap: {
      AccountMFAEnabled: 0,             // FAIL: root MFA off
      AccountSigningCertificatesPresent: 0,
      Users: 2,
      Groups: 0,
      Roles: 5,
      MFADevices: 1,
      MFADevicesInUse: 1,
    },
  },
  ListAccountAliases: { AccountAliases: ['acme-prod'] },
  ListUsers: {
    Users: [
      { UserName: 'alice.smith', Arn: 'arn:aws:iam::111122223333:user/alice.smith', UserId: 'AIDA1', CreateDate: '2023-11-08T10:15:00Z', PasswordLastUsed: '2026-05-26T22:14:00Z' },
      { UserName: 'bob.contractor', Arn: 'arn:aws:iam::111122223333:user/bob.contractor', UserId: 'AIDA2', CreateDate: '2025-08-21T14:30:00Z', PasswordLastUsed: '2026-04-30T08:45:00Z' },
    ],
    IsTruncated: false,
  },
  GetUser: (input: any) => {
    const u = input?.UserName ?? 'x';
    return { User: { UserName: u, Arn: `arn:aws:iam::111122223333:user/${u}`, UserId: `AIDA-${u}`, Tags: [] } };
  },
  // Both users have console login (both throw nothing => login profile exists)
  GetLoginProfile: (input: any) => ({ LoginProfile: { UserName: input?.UserName, CreateDate: '2023-11-08T10:15:00Z' } }),
  // alice has MFA, bob doesn't
  ListMFADevices: (input: any) => {
    if (input?.UserName === 'alice.smith') {
      return { MFADevices: [{ UserName: 'alice.smith', SerialNumber: 'arn:aws:iam::111122223333:mfa/alice.smith', EnableDate: '2023-11-09T11:00:00Z' }] };
    }
    return { MFADevices: [] };
  },
  ListAttachedUserPolicies: { AttachedPolicies: [{ PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess', PolicyName: 'ReadOnlyAccess' }] },
  ListUserPolicies: { PolicyNames: [] },
  ListVirtualMFADevices: {
    VirtualMFADevices: [
      { SerialNumber: 'arn:aws:iam::111122223333:mfa/alice.smith', User: { UserName: 'alice.smith', Arn: 'arn:aws:iam::111122223333:user/alice.smith' }, EnableDate: '2023-11-09T11:00:00Z' },
    ],
  },
  ListSAMLProviders: { SAMLProviderList: [] },       // no external IdP detected
  ListOpenIDConnectProviders: { OpenIDConnectProviderList: [] },
  ListInstances: { Instances: [] },                  // no Identity Center
  ListPolicies: { Policies: [] },                     // no SCPs
};

// Re-export the error helper in case other fixtures want to use it.
export { NoSuchEntityException };
