/**
 * IAM-MFA test fixture: an environment where everything passes.
 * Used by tests/providers/aws/iam-mfa.test.ts.
 */
import type { FakeResponses } from '../helpers/fake-aws-sdk.ts';

export const iamMfaPassing: FakeResponses = {
  // Root MFA on
  GetAccountSummary: {
    SummaryMap: {
      AccountMFAEnabled: 1,
      AccountSigningCertificatesPresent: 0,
      Users: 0,
      Groups: 0,
      Roles: 5,
      Policies: 12,
      MFADevices: 1,
      MFADevicesInUse: 1,
    },
  },
  ListAccountAliases: { AccountAliases: ['acme-prod'] },
  ListUsers: { Users: [], IsTruncated: false },  // No standalone IAM users (federated env)
  ListVirtualMFADevices: { VirtualMFADevices: [] },
  ListSAMLProviders: { SAMLProviderList: [{ Arn: 'arn:aws:iam::111122223333:saml-provider/Okta' }] },
  ListOpenIDConnectProviders: { OpenIDConnectProviderList: [{ Arn: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com' }] },
  ListInstances: { Instances: [{ InstanceArn: 'arn:aws:sso:::instance/ssoins-test', IdentityStoreId: 'd-test' }] },
  ListPolicies: {
    Policies: [{
      Id: 'p-mfa',
      Name: 'deny-no-mfa',
      Type: 'SERVICE_CONTROL_POLICY',
      AwsManaged: false,
      Arn: 'arn:aws:organizations::aws:policy/service_control_policy/p-mfa',
    }],
  },
  DescribePolicy: {
    Policy: {
      PolicySummary: { Name: 'deny-no-mfa', Type: 'SERVICE_CONTROL_POLICY' },
      Content: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
          Effect: 'Deny',
          NotAction: ['iam:GetUser', 'iam:ListMFADevices', 'sts:GetSessionToken'],
          Resource: '*',
          Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } },
        }],
      }),
    },
  },
};
