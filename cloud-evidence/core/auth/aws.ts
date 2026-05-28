/**
 * AWS client factory.
 *
 * Phase 1 uses the runner's default profile / SSO session. The runner is
 * expected to have already run `aws sso login` (if using SSO) or have
 * `AWS_PROFILE` set in the environment.
 *
 * Every client this module returns is wrapped by `wrapAwsClient` so that
 * any attempt to dispatch a non-read-only Command throws before it leaves
 * the process. See core/readonly-guardrail.ts.
 */
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { IAMClient } from '@aws-sdk/client-iam';
import { IdentitystoreClient } from '@aws-sdk/client-identitystore';
import { SSOAdminClient } from '@aws-sdk/client-sso-admin';
import { OrganizationsClient } from '@aws-sdk/client-organizations';
import { AccessAnalyzerClient } from '@aws-sdk/client-accessanalyzer';
import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { EventBridgeClient } from '@aws-sdk/client-eventbridge';
import { LambdaClient } from '@aws-sdk/client-lambda';
import { SSMClient } from '@aws-sdk/client-ssm';
import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { EC2Client } from '@aws-sdk/client-ec2';
import { ElasticLoadBalancingV2Client } from '@aws-sdk/client-elastic-load-balancing-v2';
import { S3Client } from '@aws-sdk/client-s3';
import { RDSClient } from '@aws-sdk/client-rds';
import { EKSClient } from '@aws-sdk/client-eks';
import { CloudFrontClient } from '@aws-sdk/client-cloudfront';
import { WAFV2Client } from '@aws-sdk/client-wafv2';
import { ShieldClient } from '@aws-sdk/client-shield';
import { NetworkFirewallClient } from '@aws-sdk/client-network-firewall';
import { ConfigServiceClient } from '@aws-sdk/client-config-service';
import { CloudFormationClient } from '@aws-sdk/client-cloudformation';
import { AutoScalingClient } from '@aws-sdk/client-auto-scaling';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { BackupClient } from '@aws-sdk/client-backup';
import { CloudTrailClient } from '@aws-sdk/client-cloudtrail';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { AthenaClient } from '@aws-sdk/client-athena';
import { FirehoseClient } from '@aws-sdk/client-firehose';
import { ECRClient } from '@aws-sdk/client-ecr';
import { CodePipelineClient } from '@aws-sdk/client-codepipeline';
import { CodeBuildClient } from '@aws-sdk/client-codebuild';
import { SignerClient } from '@aws-sdk/client-signer';
import { Inspector2Client } from '@aws-sdk/client-inspector2';
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { KMSClient } from '@aws-sdk/client-kms';
import { ACMClient } from '@aws-sdk/client-acm';
import { AppMeshClient } from '@aws-sdk/client-app-mesh';
import { SecurityLakeClient } from '@aws-sdk/client-securitylake';
import { ResourceExplorer2Client } from '@aws-sdk/client-resource-explorer-2';
import { ResourceGroupsTaggingAPIClient } from '@aws-sdk/client-resource-groups-tagging-api';
import { CostExplorerClient } from '@aws-sdk/client-cost-explorer';
import { Macie2Client } from '@aws-sdk/client-macie2';

import { wrapAwsClient } from '../readonly-guardrail.ts';

export interface AwsAuth {
  region: string;
  /** Credential provider chain (env, SSO, profile, etc.). */
  credentials: ReturnType<typeof fromNodeProviderChain>;
}

export function makeAwsAuth(region: string): AwsAuth {
  return {
    region,
    credentials: fromNodeProviderChain(),
  };
}

/**
 * Validate that the runner actually has credentials. Returns the account ID
 * + ARN of the calling identity. STS GetCallerIdentity is read-only.
 */
export async function whoAmI(auth: AwsAuth): Promise<{ account: string; arn: string; userId: string }> {
  const sts = wrapAwsClient(new STSClient({ region: auth.region, credentials: auth.credentials }));
  const out = await sts.send(new GetCallerIdentityCommand({}));
  return {
    account: out.Account ?? '',
    arn: out.Arn ?? '',
    userId: out.UserId ?? '',
  };
}

// ---- Client factories (all read-only-wrapped) ----

export const iam = (a: AwsAuth) =>
  wrapAwsClient(new IAMClient({ region: a.region, credentials: a.credentials }));

export const identitystore = (a: AwsAuth) =>
  wrapAwsClient(new IdentitystoreClient({ region: a.region, credentials: a.credentials }));

export const ssoadmin = (a: AwsAuth) =>
  wrapAwsClient(new SSOAdminClient({ region: a.region, credentials: a.credentials }));

export const organizations = (a: AwsAuth) =>
  wrapAwsClient(new OrganizationsClient({ region: a.region, credentials: a.credentials }));

export const accessanalyzer = (a: AwsAuth) =>
  wrapAwsClient(new AccessAnalyzerClient({ region: a.region, credentials: a.credentials }));

export const guardduty = (a: AwsAuth) =>
  wrapAwsClient(new GuardDutyClient({ region: a.region, credentials: a.credentials }));

export const securityhub = (a: AwsAuth) =>
  wrapAwsClient(new SecurityHubClient({ region: a.region, credentials: a.credentials }));

export const eventbridge = (a: AwsAuth) =>
  wrapAwsClient(new EventBridgeClient({ region: a.region, credentials: a.credentials }));

export const lambda = (a: AwsAuth) =>
  wrapAwsClient(new LambdaClient({ region: a.region, credentials: a.credentials }));

export const ssm = (a: AwsAuth) =>
  wrapAwsClient(new SSMClient({ region: a.region, credentials: a.credentials }));

export const cognito = (a: AwsAuth) =>
  wrapAwsClient(new CognitoIdentityProviderClient({ region: a.region, credentials: a.credentials }));

export const ec2 = (a: AwsAuth) => wrapAwsClient(new EC2Client({ region: a.region, credentials: a.credentials }));
export const elbv2 = (a: AwsAuth) => wrapAwsClient(new ElasticLoadBalancingV2Client({ region: a.region, credentials: a.credentials }));
export const s3 = (a: AwsAuth) => wrapAwsClient(new S3Client({ region: a.region, credentials: a.credentials }));
export const rds = (a: AwsAuth) => wrapAwsClient(new RDSClient({ region: a.region, credentials: a.credentials }));
export const eks = (a: AwsAuth) => wrapAwsClient(new EKSClient({ region: a.region, credentials: a.credentials }));
export const cloudfront = (a: AwsAuth) => wrapAwsClient(new CloudFrontClient({ region: a.region, credentials: a.credentials }));
export const wafv2 = (a: AwsAuth) => wrapAwsClient(new WAFV2Client({ region: a.region, credentials: a.credentials }));
export const shield = (a: AwsAuth) => wrapAwsClient(new ShieldClient({ region: a.region, credentials: a.credentials }));
export const networkFirewall = (a: AwsAuth) => wrapAwsClient(new NetworkFirewallClient({ region: a.region, credentials: a.credentials }));
export const configService = (a: AwsAuth) => wrapAwsClient(new ConfigServiceClient({ region: a.region, credentials: a.credentials }));
export const cloudformation = (a: AwsAuth) => wrapAwsClient(new CloudFormationClient({ region: a.region, credentials: a.credentials }));
export const autoScaling = (a: AwsAuth) => wrapAwsClient(new AutoScalingClient({ region: a.region, credentials: a.credentials }));
export const dynamodb = (a: AwsAuth) => wrapAwsClient(new DynamoDBClient({ region: a.region, credentials: a.credentials }));
export const backup = (a: AwsAuth) => wrapAwsClient(new BackupClient({ region: a.region, credentials: a.credentials }));

export const cloudtrail = (a: AwsAuth) => wrapAwsClient(new CloudTrailClient({ region: a.region, credentials: a.credentials }));
export const cloudwatchlogs = (a: AwsAuth) => wrapAwsClient(new CloudWatchLogsClient({ region: a.region, credentials: a.credentials }));
export const athena = (a: AwsAuth) => wrapAwsClient(new AthenaClient({ region: a.region, credentials: a.credentials }));
export const firehose = (a: AwsAuth) => wrapAwsClient(new FirehoseClient({ region: a.region, credentials: a.credentials }));
export const ecr = (a: AwsAuth) => wrapAwsClient(new ECRClient({ region: a.region, credentials: a.credentials }));
export const codepipeline = (a: AwsAuth) => wrapAwsClient(new CodePipelineClient({ region: a.region, credentials: a.credentials }));
export const codebuild = (a: AwsAuth) => wrapAwsClient(new CodeBuildClient({ region: a.region, credentials: a.credentials }));
export const signer = (a: AwsAuth) => wrapAwsClient(new SignerClient({ region: a.region, credentials: a.credentials }));
export const inspector2 = (a: AwsAuth) => wrapAwsClient(new Inspector2Client({ region: a.region, credentials: a.credentials }));
export const secretsmanager = (a: AwsAuth) => wrapAwsClient(new SecretsManagerClient({ region: a.region, credentials: a.credentials }));
export const kms = (a: AwsAuth) => wrapAwsClient(new KMSClient({ region: a.region, credentials: a.credentials }));
export const acm = (a: AwsAuth) => wrapAwsClient(new ACMClient({ region: a.region, credentials: a.credentials }));
export const appmesh = (a: AwsAuth) => wrapAwsClient(new AppMeshClient({ region: a.region, credentials: a.credentials }));
export const securitylake = (a: AwsAuth) => wrapAwsClient(new SecurityLakeClient({ region: a.region, credentials: a.credentials }));
export const resourceExplorer = (a: AwsAuth) => wrapAwsClient(new ResourceExplorer2Client({ region: a.region, credentials: a.credentials }));
export const taggingApi = (a: AwsAuth) => wrapAwsClient(new ResourceGroupsTaggingAPIClient({ region: a.region, credentials: a.credentials }));
export const costExplorer = (a: AwsAuth) => wrapAwsClient(new CostExplorerClient({ region: a.region, credentials: a.credentials }));
export const macie = (a: AwsAuth) => wrapAwsClient(new Macie2Client({ region: a.region, credentials: a.credentials }));
