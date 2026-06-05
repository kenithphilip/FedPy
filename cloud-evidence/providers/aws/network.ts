/**
 * AWS network-domain CNA collectors.
 * Covers:
 *   - KSI-CNA-MAT — Minimizing Attack Surface
 *   - KSI-CNA-RNT — Restricting Network Traffic (in/out)
 *   - KSI-CNA-ULN — Using Logical Networking
 *   - KSI-CNA-RVP — Reviewing Protections (DoS)
 *
 * Read-only — every SDK client is wrapped by core/readonly-guardrail.ts.
 */
import {
  DescribeSecurityGroupsCommand,
  DescribeInstancesCommand,
  DescribeVpcsCommand,
  DescribeSubnetsCommand,
  DescribeRouteTablesCommand,
  DescribeNetworkAclsCommand,
  DescribeFlowLogsCommand,
  DescribeVpcEndpointsCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeTransitGatewaysCommand,
} from '@aws-sdk/client-ec2';
import { DescribeLoadBalancersCommand as DescribeLBsCommand, DescribeListenersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ListDistributionsCommand, GetDistributionCommand } from '@aws-sdk/client-cloudfront';
import { ListBucketsCommand, GetBucketPolicyStatusCommand } from '@aws-sdk/client-s3';
import { DescribeDBInstancesCommand, DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { ListClustersCommand as EksListClustersCommand, DescribeClusterCommand as EksDescribeClusterCommand } from '@aws-sdk/client-eks';
import { GetPolicyCommand as LambdaGetPolicyCommand, ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { ListWebACLsCommand, GetWebACLCommand } from '@aws-sdk/client-wafv2';
import { GetSubscriptionStateCommand } from '@aws-sdk/client-shield';
import { ListFirewallsCommand } from '@aws-sdk/client-network-firewall';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

const DEFAULT_REGION = 'us-east-1';
const ADMIN_PORTS = [22, 3389, 3306, 5432, 6379, 27017, 9200];

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }

async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? DEFAULT_REGION;
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) {
    try { account = (await aws.whoAmI(auth)).account; } catch { account = null; }
  }
  return { region, auth, account };
}

// -------- Shared inventory (one fetch per call; multiple KSIs reuse this) --------
interface NetworkInventory {
  securityGroups: any[];
  instances: any[];
  vpcs: any[];
  subnets: any[];
  routeTables: any[];
  networkAcls: any[];
  flowLogs: any[];
  vpcEndpoints: any[];
  peeringConnections: any[];
  transitGateways: any[];
  loadBalancers: any[];
  s3Buckets: any[];
  s3PublicBuckets: string[];
  rdsInstances: any[];
  rdsClusters: any[];
  eksClusters: any[];
  lambdaFunctions: any[];
  lambdasWithPublicPrincipals: any[];
  wafWebAcls: any[];
  shieldAdvancedActive: boolean;
  networkFirewalls: any[];
}

async function fetchNetworkInventory(ctx: Ctx): Promise<{ inv: NetworkInventory; warnings: string[]; evidence: RawEvidence[] }> {
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const inv: NetworkInventory = {
    securityGroups: [], instances: [], vpcs: [], subnets: [], routeTables: [], networkAcls: [],
    flowLogs: [], vpcEndpoints: [], peeringConnections: [], transitGateways: [],
    loadBalancers: [], s3Buckets: [], s3PublicBuckets: [], rdsInstances: [], rdsClusters: [],
    eksClusters: [], lambdaFunctions: [], lambdasWithPublicPrincipals: [], wafWebAcls: [],
    shieldAdvancedActive: false, networkFirewalls: [],
  };

  const ec2 = aws.ec2(ctx.auth);
  try {
    const r = await ec2.send(new DescribeSecurityGroupsCommand({ MaxResults: 1000 }));
    inv.securityGroups = r.SecurityGroups ?? [];
    evidence.push(ev('ec2.DescribeSecurityGroups', { count: inv.securityGroups.length }));
  } catch (e: any) { warnings.push(`DescribeSecurityGroups: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeInstancesCommand({ MaxResults: 200 }));
    inv.instances = (r.Reservations ?? []).flatMap((res: any) => res.Instances ?? []);
    evidence.push(ev('ec2.DescribeInstances', { count: inv.instances.length }));
  } catch (e: any) { warnings.push(`DescribeInstances: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeVpcsCommand({}));
    inv.vpcs = r.Vpcs ?? [];
    evidence.push(ev('ec2.DescribeVpcs', { count: inv.vpcs.length }));
  } catch (e: any) { warnings.push(`DescribeVpcs: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeSubnetsCommand({}));
    inv.subnets = r.Subnets ?? [];
  } catch (e: any) { warnings.push(`DescribeSubnets: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeRouteTablesCommand({}));
    inv.routeTables = r.RouteTables ?? [];
  } catch (e: any) { warnings.push(`DescribeRouteTables: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeNetworkAclsCommand({}));
    inv.networkAcls = r.NetworkAcls ?? [];
  } catch (e: any) { warnings.push(`DescribeNetworkAcls: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeFlowLogsCommand({}));
    inv.flowLogs = r.FlowLogs ?? [];
    evidence.push(ev('ec2.DescribeFlowLogs', { count: inv.flowLogs.length }));
  } catch (e: any) { warnings.push(`DescribeFlowLogs: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeVpcEndpointsCommand({}));
    inv.vpcEndpoints = r.VpcEndpoints ?? [];
  } catch (e: any) { warnings.push(`DescribeVpcEndpoints: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeVpcPeeringConnectionsCommand({}));
    inv.peeringConnections = r.VpcPeeringConnections ?? [];
  } catch (e: any) { warnings.push(`DescribeVpcPeeringConnections: ${e.message}`); }

  try {
    const r = await ec2.send(new DescribeTransitGatewaysCommand({}));
    inv.transitGateways = r.TransitGateways ?? [];
  } catch (e: any) { warnings.push(`DescribeTransitGateways: ${e.message}`); }

  try {
    const elb = aws.elbv2(ctx.auth);
    const r = await elb.send(new DescribeLBsCommand({}));
    inv.loadBalancers = r.LoadBalancers ?? [];
    evidence.push(ev('elbv2.DescribeLoadBalancers', { count: inv.loadBalancers.length }));
  } catch (e: any) { warnings.push(`DescribeLoadBalancers: ${e.message}`); }

  try {
    const s3 = aws.s3(ctx.auth);
    const r = await s3.send(new ListBucketsCommand({}));
    inv.s3Buckets = r.Buckets ?? [];
    for (const b of inv.s3Buckets) {
      if (!b.Name) continue;
      try {
        const st = await s3.send(new GetBucketPolicyStatusCommand({ Bucket: b.Name }));
        if (st.PolicyStatus?.IsPublic) inv.s3PublicBuckets.push(b.Name);
      } catch { /* no policy = not public via policy */ }
    }
    evidence.push(ev('s3.bucket_public_status', { total: inv.s3Buckets.length, public_via_policy: inv.s3PublicBuckets }));
  } catch (e: any) { warnings.push(`S3 inventory: ${e.message}`); }

  try {
    const rds = aws.rds(ctx.auth);
    const r = await rds.send(new DescribeDBInstancesCommand({}));
    inv.rdsInstances = r.DBInstances ?? [];
    const c = await rds.send(new DescribeDBClustersCommand({}));
    inv.rdsClusters = c.DBClusters ?? [];
    evidence.push(ev('rds.inventory', { instances: inv.rdsInstances.length, clusters: inv.rdsClusters.length }));
  } catch (e: any) { warnings.push(`RDS: ${e.message}`); }

  try {
    const eks = aws.eks(ctx.auth);
    const lst = await eks.send(new EksListClustersCommand({}));
    for (const name of lst.clusters ?? []) {
      const d = await eks.send(new EksDescribeClusterCommand({ name }));
      if (d.cluster) inv.eksClusters.push(d.cluster);
    }
    evidence.push(ev('eks.cluster_inventory', inv.eksClusters.filter((c: any) => c?.name).map((c: any) => ({ name: c.name, endpointPublicAccess: c.resourcesVpcConfig?.endpointPublicAccess, publicAccessCidrs: c.resourcesVpcConfig?.publicAccessCidrs }))));
  } catch (e: any) { warnings.push(`EKS: ${e.message}`); }

  try {
    const lambda = aws.lambda(ctx.auth);
    let tok: string | undefined;
    do {
      const r = await lambda.send(new ListFunctionsCommand({ Marker: tok, MaxItems: 50 }));
      inv.lambdaFunctions.push(...(r.Functions ?? []));
      tok = r.NextMarker;
    } while (tok);
    for (const f of inv.lambdaFunctions) {
      if (!f.FunctionName) continue;
      try {
        const p = await lambda.send(new LambdaGetPolicyCommand({ FunctionName: f.FunctionName }));
        // p.Policy is a JSON string. Defensive parse so a truncated/malformed
        // policy is logged as a warning, not silently swallowed (which would
        // hide a public-principal misconfiguration).
        let doc: any = { Statement: [] };
        try {
          doc = JSON.parse(p.Policy ?? '{}');
        } catch (parseErr: any) {
          warnings.push(`Lambda ${f.FunctionName} policy JSON malformed: ${parseErr.message}`);
          continue;
        }
        for (const s of doc.Statement ?? []) {
          const principal = s.Principal?.AWS ?? s.Principal ?? null;
          if (principal === '*' && !s.Condition) inv.lambdasWithPublicPrincipals.push({ function: f.FunctionName, statement: s });
        }
      } catch (e: any) {
        // Most common: ResourceNotFoundException — the function has no resource policy.
        // That's expected and not an error to surface unless it's something else.
        if (e?.name !== 'ResourceNotFoundException' && e?.code !== 'ResourceNotFoundException') {
          warnings.push(`Lambda GetPolicy ${f.FunctionName}: ${e?.name ?? 'unknown'}: ${e?.message}`);
        }
      }
    }
    evidence.push(ev('lambda.public_principal_audit', { total: inv.lambdaFunctions.length, public: inv.lambdasWithPublicPrincipals.length }));
  } catch (e: any) { warnings.push(`Lambda: ${e.message}`); }

  try {
    const waf = aws.wafv2(ctx.auth);
    const r = await waf.send(new ListWebACLsCommand({ Scope: 'REGIONAL' }));
    inv.wafWebAcls = r.WebACLs ?? [];
    evidence.push(ev('wafv2.ListWebACLs', { count: inv.wafWebAcls.length }));
  } catch (e: any) { warnings.push(`WAFv2: ${e.message}`); }

  try {
    const sh = aws.shield(ctx.auth);
    const st = await sh.send(new GetSubscriptionStateCommand({}));
    inv.shieldAdvancedActive = st.SubscriptionState === 'ACTIVE';
    evidence.push(ev('shield.GetSubscriptionState', st));
  } catch (e: any) { warnings.push(`Shield: ${e.message}`); }

  try {
    const nfw = aws.networkFirewall(ctx.auth);
    const r = await nfw.send(new ListFirewallsCommand({}));
    inv.networkFirewalls = r.Firewalls ?? [];
    evidence.push(ev('network-firewall.ListFirewalls', { count: inv.networkFirewalls.length }));
  } catch (e: any) { warnings.push(`Network Firewall: ${e.message}`); }

  return { inv, warnings, evidence };
}

// =====================================================================
// KSI-CNA-MAT — Minimizing Attack Surface
// =====================================================================
export async function collectCnaMat(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { inv, warnings, evidence } = await fetchNetworkInventory(ctx);

  const sgOpenToWorldAdmin: Array<{ groupId: string; vpc: string; port: number; cidr: string }> = [];
  for (const sg of inv.securityGroups) {
    for (const perm of sg.IpPermissions ?? []) {
      const from = perm.FromPort ?? 0;
      const to = perm.ToPort ?? 65535;
      if (perm.IpProtocol !== '-1' && perm.IpProtocol !== 'tcp' && perm.IpProtocol !== 'udp') continue;
      for (const range of perm.IpRanges ?? []) {
        if (range.CidrIp === '0.0.0.0/0') {
          for (const port of ADMIN_PORTS) {
            if (port >= from && port <= to) {
              sgOpenToWorldAdmin.push({ groupId: sg.GroupId, vpc: sg.VpcId, port, cidr: range.CidrIp });
            }
          }
        }
      }
    }
  }

  const ec2WithoutImdsv2 = inv.instances.filter((i: any) => i.MetadataOptions?.HttpTokens !== 'required').map((i: any) => i.InstanceId);
  const rdsPublic = inv.rdsInstances.filter((i: any) => i.PubliclyAccessible === true).map((i: any) => i.DBInstanceIdentifier);
  const eksPublicEndpoint = inv.eksClusters.filter((c: any) => c.resourcesVpcConfig?.endpointPublicAccess === true);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External CNAPP / CSPM (Wiz, Lacework, Prisma Cloud)',
      description: 'A CSPM/CNAPP tool may track attack-surface signals continuously.',
      evidence_required: ['CSPM tool tenant ID', 'Recent attack-surface report export', 'Representative finding lifecycle'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.sg.no_world_open_to_admin_ports',
      passed: sgOpenToWorldAdmin.length === 0,
      severity: 'critical',
      current: {
        summary: sgOpenToWorldAdmin.length === 0
          ? `No security group allows 0.0.0.0/0 to admin ports (${ADMIN_PORTS.join(',')}) across ${inv.securityGroups.length} groups.`
          : `${sgOpenToWorldAdmin.length} security-group rule(s) allow 0.0.0.0/0 to administrative ports.`,
        observations: { total_security_groups: inv.securityGroups.length, violations: sgOpenToWorldAdmin },
      },
      target: { summary: 'Zero SG rules allow 0.0.0.0/0 to admin ports (22,3389,3306,5432,6379,27017,9200).', rationale: 'NIST SC-7 / SC-7(5). World-open admin ports are scanned + exploited within hours.' },
      gap: sgOpenToWorldAdmin.length === 0 ? undefined : {
        description: 'Each listed rule exposes a sensitive port to the internet.',
        affected_resources: sgOpenToWorldAdmin.map<AffectedResource>((s) => ({
          type: 'aws_security_group_rule', identifier: `${s.groupId}:${s.port}`, name: `${s.groupId}:${s.port}`,
          attributes: { vpc: s.vpc, port: s.port, cidr: s.cidr },
        })),
      },
      remediation: sgOpenToWorldAdmin.length === 0 ? undefined : {
        summary: 'Remove 0.0.0.0/0 admin-port rules; adopt Session Manager / VPN / bastion.',
        options: [{
          approach: 'Remove world-open admin rules + adopt SSM Session Manager.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'No additional charges.' },
          availability_impact: { level: 'medium', notes: 'Anyone using SSH from arbitrary IPs will be locked out. Pre-announce.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-SG audit + alternative-access setup.' },
          steps: [
            'For each violating SG, audit legitimate access patterns via CloudTrail / VPC Flow Logs.',
            'Stand up SSM Session Manager (no SSH key needed) OR a hardened bastion + VPN.',
            'Remove the 0.0.0.0/0 ingress rule via Terraform.',
            'Validate operators can still reach instances via the new path.',
          ],
          example_code: `# Remove rules like:
# resource "aws_security_group_rule" "ssh_world" {
#   type        = "ingress"
#   from_port   = 22
#   to_port     = 22
#   protocol    = "tcp"
#   cidr_blocks = ["0.0.0.0/0"]
#   security_group_id = aws_security_group.app.id
# }
# Replace with SSM Session Manager (zero ingress required).`,
          references: [{ title: 'AWS docs: Session Manager', url: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['sc-7','sc-7.5','ac-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-RNT', relationship: 'shares-remediation', note: 'Same SG fixes contribute to network-traffic restriction.' },
        { ksi_id: 'KSI-IAM-JIT', relationship: 'shares-remediation', note: 'Session Manager IS the JIT shell-access primitive.' },
      ],
    }),

    finding({
      rule: 'aws.ec2.all_imdsv2_required',
      passed: ec2WithoutImdsv2.length === 0,
      severity: 'high',
      current: {
        summary: ec2WithoutImdsv2.length === 0
          ? `All ${inv.instances.length} EC2 instances enforce IMDSv2.`
          : `${ec2WithoutImdsv2.length} of ${inv.instances.length} EC2 instances allow IMDSv1.`,
        observations: { total_instances: inv.instances.length, instances_without_imdsv2: ec2WithoutImdsv2 },
      },
      target: { summary: 'All EC2 instances have MetadataOptions.HttpTokens="required" (IMDSv2 only).', rationale: 'IMDSv1 is exploitable via SSRF (Capital One breach pattern). NIST SC-7.' },
      gap: ec2WithoutImdsv2.length === 0 ? undefined : {
        description: 'IMDSv1 allows credential retrieval via unauthenticated metadata fetch — exploitable via app SSRF.',
        affected_resources: ec2WithoutImdsv2.map<AffectedResource>((id: string) => ({
          type: 'aws_instance', identifier: id, name: id, attributes: {},
        })),
      },
      remediation: ec2WithoutImdsv2.length === 0 ? undefined : {
        summary: 'Modify each instance to require IMDSv2 (in-place change).',
        options: [{
          approach: 'Set HttpTokens=required via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'No charge.' },
          availability_impact: { level: 'low', notes: 'Modern AWS SDKs handle IMDSv2 transparently. Audit for hand-rolled metadata callers.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Apply Terraform; validate.' },
          steps: ['Audit hand-rolled metadata calls.', 'Apply metadata_options block.', 'Verify with curl that v1 fails.'],
          example_code: `resource "aws_instance" "app" {
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 1
  }
}`,
          references: [{ title: 'AWS docs: IMDSv2', url: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','si-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'IMDSv2 protects instance-role credentials.' },
      ],
    }),

    finding({
      rule: 'aws.s3.no_public_buckets',
      passed: inv.s3PublicBuckets.length === 0,
      severity: 'critical',
      current: {
        summary: inv.s3PublicBuckets.length === 0
          ? `No public buckets among ${inv.s3Buckets.length} total.`
          : `${inv.s3PublicBuckets.length} bucket(s) are public per their policy status.`,
        observations: { total_buckets: inv.s3Buckets.length, public_buckets: inv.s3PublicBuckets },
      },
      target: { summary: 'Zero public S3 buckets unless explicitly intended + documented.', rationale: 'NIST AC-3, SC-7. Public buckets = #1 cause of cloud data breaches.' },
      gap: inv.s3PublicBuckets.length === 0 ? undefined : {
        description: 'Public buckets expose data to the internet — auditor red flag.',
        affected_resources: inv.s3PublicBuckets.map<AffectedResource>((name) => ({
          type: 'aws_s3_bucket', identifier: name, name, attributes: {},
        })),
      },
      remediation: inv.s3PublicBuckets.length === 0 ? undefined : {
        summary: 'Apply account-level Block Public Access; review each public bucket\'s intent.',
        options: [{
          approach: 'Enable account-level S3 BPA + audit exempt buckets.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'high', notes: 'If a bucket is intentionally public (e.g. static website), this will break it without explicit exemption.' },
          customer_visible: { level: 'medium', notes: 'Public-website buckets become unavailable if not migrated to CloudFront-fronted.' },
          effort_estimate: { magnitude: 'days', notes: 'Audit each public bucket\'s intent first.' },
          steps: [
            'Inventory each public bucket\'s intent (static site, CDN origin, partner integration).',
            'For intentional ones, move them behind CloudFront with OAC (bucket itself becomes private).',
            'Enable account-level Block Public Access.',
            'Re-test customer-facing endpoints.',
          ],
          example_code: `resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
          references: [{ title: 'S3 Block Public Access', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','sc-7'],
    }),

    finding({
      rule: 'aws.lambda.no_public_invocation',
      passed: inv.lambdasWithPublicPrincipals.length === 0,
      severity: 'high',
      current: {
        summary: inv.lambdasWithPublicPrincipals.length === 0
          ? `No Lambdas with unconditional Principal:* across ${inv.lambdaFunctions.length} functions.`
          : `${inv.lambdasWithPublicPrincipals.length} Lambda(s) allow Principal:* without conditions.`,
        observations: { violations: inv.lambdasWithPublicPrincipals },
      },
      target: { summary: 'No Lambda has a resource policy with Principal:* and no Condition.', rationale: 'NIST AC-3. Unauthenticated invocation = world-callable function.' },
      gap: inv.lambdasWithPublicPrincipals.length === 0 ? undefined : {
        description: 'Each listed function is invocable by anyone with the function URL or ARN.',
        affected_resources: inv.lambdasWithPublicPrincipals.map<AffectedResource>((l: any) => ({
          type: 'aws_lambda_function', identifier: l.function, name: l.function, attributes: { statement: l.statement },
        })),
      },
      remediation: inv.lambdasWithPublicPrincipals.length === 0 ? undefined : {
        summary: 'Scope the resource policy or require IAM auth on function URLs.',
        options: [{
          approach: 'Set function URL auth_type=AWS_IAM; remove wildcard statements.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Existing public clients of the function must now authenticate.' },
          customer_visible: { level: 'medium', notes: 'If function is a customer-facing API endpoint, customers need auth.' },
          effort_estimate: { magnitude: 'days', notes: 'Per function.' },
          steps: ['Identify legitimate callers.', 'Either set function URL auth_type=AWS_IAM, OR front with API Gateway + authorizer.', 'Remove the wildcard statement.'],
          example_code: `resource "aws_lambda_function_url" "this" {
  function_name      = aws_lambda_function.app.function_name
  authorization_type = "AWS_IAM"
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3'],
    }),

    finding({
      rule: 'aws.rds.no_public_instances',
      passed: rdsPublic.length === 0,
      severity: 'high',
      current: {
        summary: rdsPublic.length === 0
          ? `No publicly-accessible RDS instances among ${inv.rdsInstances.length} total.`
          : `${rdsPublic.length} RDS instance(s) are PubliclyAccessible=true.`,
        observations: { violations: rdsPublic },
      },
      target: { summary: 'No prod RDS instance has PubliclyAccessible=true.', rationale: 'NIST SC-7. Public DBs are scanned and brute-forced.' },
      gap: rdsPublic.length === 0 ? undefined : {
        description: 'Database internet exposure.',
        affected_resources: rdsPublic.map<AffectedResource>((id: string) => ({ type: 'aws_db_instance', identifier: id, name: id, attributes: {} })),
      },
      remediation: rdsPublic.length === 0 ? undefined : {
        summary: 'Disable PubliclyAccessible; use PrivateLink / peering / Transit Gateway for cross-VPC access.',
        options: [{
          approach: 'Set publicly_accessible=false via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'No additional charges.' },
          availability_impact: { level: 'medium', notes: 'External clients via public DNS must move to private connectivity. Brief downtime.' },
          customer_visible: { level: 'low', notes: 'Only affects external integrations.' },
          effort_estimate: { magnitude: 'days', notes: 'Per instance.' },
          steps: ['Identify external clients.', 'Stand up alternative connectivity.', 'Set publicly_accessible=false.'],
          example_code: `resource "aws_db_instance" "app" {
  publicly_accessible = false
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7'],
    }),

    finding({
      rule: 'aws.eks.no_public_endpoint',
      passed: eksPublicEndpoint.length === 0,
      severity: 'high',
      current: {
        summary: eksPublicEndpoint.length === 0
          ? `No EKS clusters expose public endpoints among ${inv.eksClusters.length} total.`
          : `${eksPublicEndpoint.length} EKS cluster(s) have public-endpoint access (Kubernetes API exposed).`,
        observations: { clusters: eksPublicEndpoint.map((c: any) => ({ name: c.name, publicAccessCidrs: c.resourcesVpcConfig?.publicAccessCidrs })) },
      },
      target: { summary: 'EKS public endpoint disabled, OR restricted to a small CIDR allowlist.', rationale: 'NIST SC-7. Public K8s API = potential RCE surface.' },
      gap: eksPublicEndpoint.length === 0 ? undefined : {
        description: 'Kubernetes API exposed to the internet.',
        affected_resources: eksPublicEndpoint.map<AffectedResource>((c: any) => ({
          type: 'aws_eks_cluster', identifier: c.arn, name: c.name,
          attributes: { publicAccessCidrs: c.resourcesVpcConfig?.publicAccessCidrs },
        })),
      },
      remediation: eksPublicEndpoint.length === 0 ? undefined : {
        summary: 'Disable public endpoint, OR restrict publicAccessCidrs to a tight allowlist.',
        options: [{
          approach: 'Switch to private endpoint via bastion / VPN.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Operators must use VPN/bastion for kubectl.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Alternative access path setup.' },
          steps: ['Set up bastion / VPN.', 'Update Terraform: endpoint_public_access=false, endpoint_private_access=true.', 'Apply.'],
          example_code: `resource "aws_eks_cluster" "this" {
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','ac-3'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-RNT — Restricting Network Traffic (inbound + outbound)
// =====================================================================
export async function collectCnaRnt(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { inv, warnings, evidence } = await fetchNetworkInventory(ctx);

  const defaultSgUnrestrictedEgress: Array<{ groupId: string; vpc: string }> = [];
  const nonDefaultSgUnrestrictedEgress: Array<{ groupId: string; vpc: string }> = [];
  for (const sg of inv.securityGroups) {
    const hasOpenEgress = (sg.IpPermissionsEgress ?? []).some((p: any) =>
      p.IpProtocol === '-1' && (p.IpRanges ?? []).some((r: any) => r.CidrIp === '0.0.0.0/0')
    );
    if (hasOpenEgress) {
      if (sg.GroupName === 'default') defaultSgUnrestrictedEgress.push({ groupId: sg.GroupId, vpc: sg.VpcId });
      else nonDefaultSgUnrestrictedEgress.push({ groupId: sg.GroupId, vpc: sg.VpcId });
    }
  }

  const vpcsWithoutFlowLogs = inv.vpcs.filter((v: any) =>
    !inv.flowLogs.some((f: any) => f.ResourceId === v.VpcId)
  ).map((v: any) => v.VpcId);

  const findings = [
    finding({
      rule: 'aws.sg.default_no_unrestricted_egress',
      passed: defaultSgUnrestrictedEgress.length === 0,
      severity: 'high',
      current: {
        summary: defaultSgUnrestrictedEgress.length === 0
          ? 'Default security groups do not allow unrestricted egress.'
          : `${defaultSgUnrestrictedEgress.length} default SG(s) allow unrestricted egress (0.0.0.0/0).`,
        observations: { violations: defaultSgUnrestrictedEgress, non_default_unrestricted_count: nonDefaultSgUnrestrictedEgress.length },
      },
      target: { summary: 'Every default SG has no egress rules.', rationale: 'NIST SC-7(5) deny-by-default. The default SG is a safety net.' },
      gap: defaultSgUnrestrictedEgress.length === 0 ? undefined : {
        description: 'Any resource accidentally attached to the default SG inherits unrestricted egress.',
        affected_resources: defaultSgUnrestrictedEgress.map<AffectedResource>((s) => ({
          type: 'aws_default_security_group', identifier: s.groupId, name: 'default', attributes: { vpc: s.vpc },
        })),
      },
      remediation: defaultSgUnrestrictedEgress.length === 0 ? undefined : {
        summary: 'Remove default SG egress rules via Terraform.',
        options: [{
          approach: 'Manage default SG in Terraform with empty rule lists.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Resources legitimately depending on default SG (unusual) will lose access.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Inventory default SG attachments (should be none).', 'Apply Terraform.', 'Validate.'],
          example_code: `resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.this.id
  # no ingress + no egress rules
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','sc-7.5'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'Same SG hygiene problem.' },
      ],
    }),

    finding({
      rule: 'aws.network_firewall_or_equivalent',
      passed: inv.networkFirewalls.length >= 1,
      severity: 'medium',
      current: {
        summary: inv.networkFirewalls.length >= 1
          ? `${inv.networkFirewalls.length} AWS Network Firewall(s) deployed.`
          : 'No AWS Network Firewall — egress filtering relies on per-SG rules only.',
        observations: { network_firewalls: inv.networkFirewalls.length, non_default_sg_unrestricted_egress: nonDefaultSgUnrestrictedEgress.length },
      },
      target: { summary: 'Centralized egress-filtering capability in place (Network Firewall, NAT proxy, or 3rd-party gateway).', rationale: 'Per-SG egress hygiene drifts; centralized policy is more durable. NIST AC-4.' },
      gap: inv.networkFirewalls.length >= 1 ? undefined : {
        description: 'No centralized egress filter — exfiltration via any compromised instance is harder to block.',
        affected_resources: [{ type: 'aws_networkfirewall_firewall', identifier: 'none', attributes: {} }],
      },
      remediation: inv.networkFirewalls.length >= 1 ? undefined : {
        summary: 'Deploy AWS Network Firewall with allowlist stateful rules.',
        options: [{
          approach: 'Deploy Network Firewall via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'high', notes: 'Network Firewall: per endpoint-hour + GB processed. Hundreds-thousands/month per VPC.' },
          availability_impact: { level: 'medium', notes: 'Misconfigured rules block legitimate traffic; canary first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Modeling allowed-egress; gradual rule tuning.' },
          steps: ['Define allowed-egress FQDN/IP list.', 'Deploy in inspection VPC.', 'Route prod egress through firewall via TGW.', 'Monitor-only for 2-4 weeks.', 'Promote to enforce.'],
          references: [{ title: 'AWS Network Firewall', url: 'https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: 'Cloud-native NAT + 3rd-party egress proxy', description: '3rd-party egress proxy can substitute.', evidence_required: ['proxy config showing allowlist'], detected: false },
      ],
      nist_controls: ['ac-4','sc-7'],
    }),

    finding({
      rule: 'aws.vpc_flow_logs_enabled_all_vpcs',
      passed: vpcsWithoutFlowLogs.length === 0,
      severity: 'high',
      current: {
        summary: vpcsWithoutFlowLogs.length === 0
          ? `All ${inv.vpcs.length} VPC(s) have flow logs.`
          : `${vpcsWithoutFlowLogs.length} of ${inv.vpcs.length} VPCs do not have flow logs.`,
        observations: { total_vpcs: inv.vpcs.length, vpcs_without_flow_logs: vpcsWithoutFlowLogs },
      },
      target: { summary: 'Every in-scope VPC has VPC Flow Logs delivered to S3 / CW Logs.', rationale: 'NIST AU-2, SI-4. No flow logs = no network-flow forensics.' },
      gap: vpcsWithoutFlowLogs.length === 0 ? undefined : {
        description: 'Network-flow forensics impossible for these VPCs.',
        affected_resources: vpcsWithoutFlowLogs.map<AffectedResource>((id: string) => ({ type: 'aws_vpc', identifier: id, name: id, attributes: {} })),
      },
      remediation: vpcsWithoutFlowLogs.length === 0 ? undefined : {
        summary: 'Enable VPC Flow Logs to an S3 bucket with KMS encryption.',
        options: [{
          approach: 'Enable Flow Logs via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Per-GB ingested + stored. For busy VPCs, $hundreds/month.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform per VPC.' },
          steps: ['Apply Terraform.', 'Verify logs flowing.'],
          example_code: `resource "aws_flow_log" "this" {
  iam_role_arn         = aws_iam_role.flow_log.arn
  log_destination      = aws_s3_bucket.flow_logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = each.value
  for_each             = toset(data.aws_vpcs.all.ids)
}`,
          references: [{ title: 'VPC Flow Logs', url: 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'VPC flow logs are a primary logged-event-type.' },
        { ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Flow logs are part of the log inventory.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-ULN — Using Logical Networking
// =====================================================================
export async function collectCnaUln(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { inv, warnings, evidence } = await fetchNetworkInventory(ctx);

  const requiredVpcEndpointServices = ['s3', 'kms', 'secretsmanager', 'logs', 'sts'];
  const presentEndpointServices = new Set(inv.vpcEndpoints.map((e: any) =>
    (e.ServiceName ?? '').replace(/^com\.amazonaws\.[^.]+\./, '')
  ));
  const missingEndpoints = requiredVpcEndpointServices.filter((s) => !presentEndpointServices.has(s));

  const findings = [
    finding({
      rule: 'aws.vpc.in_scope_logical_separation',
      passed: inv.vpcs.length >= 1,
      severity: 'medium',
      current: {
        summary: `${inv.vpcs.length} VPC(s) found.`,
        observations: {
          vpcs: inv.vpcs.map((v: any) => ({ id: v.VpcId, cidr: v.CidrBlock, tags: v.Tags })),
          subnets_count: inv.subnets.length,
          peering_count: inv.peeringConnections.length,
          transit_gateways: inv.transitGateways.length,
        },
      },
      target: { summary: 'At least one VPC per environment (prod vs nonprod) with documented inter-VPC connectivity.', rationale: 'NIST SC-32 (system partitioning).' },
      gap: inv.vpcs.length >= 1 ? undefined : {
        description: 'No VPCs found — unusual; verify account scope.',
        affected_resources: [],
      },
      remediation: inv.vpcs.length >= 1 ? undefined : {
        summary: 'Verify the runner has correct account scope or create the required environment VPCs.',
        options: [{
          approach: 'Confirm the AWS account / region targeted is the right one; if so, provision a VPC with public + private subnets per env.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          steps: [
            'Confirm `aws sts get-caller-identity` matches the expected account.',
            'If account is empty by design, document as inherited / out-of-scope.',
            'Otherwise: create VPC + subnets in the configured region.',
          ],
          cost_impact: { level: 'none', notes: 'VPCs themselves are free; private subnet NAT incurs cost.' },
          availability_impact: { level: 'low', notes: 'Net-new infra.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'For a baseline VPC.' },
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','sc-32'],
    }),

    finding({
      rule: 'aws.vpc_endpoints.private_to_aws_services',
      passed: missingEndpoints.length === 0,
      severity: 'medium',
      current: {
        summary: missingEndpoints.length === 0
          ? `VPC endpoints present for all critical services: ${requiredVpcEndpointServices.join(',')}.`
          : `Missing VPC endpoints for: ${missingEndpoints.join(',')}.`,
        observations: { present: Array.from(presentEndpointServices), missing: missingEndpoints },
      },
      target: { summary: 'VPC interface/gateway endpoints exist for S3, KMS, Secrets Manager, CW Logs, STS at minimum.', rationale: 'Keeps in-VPC traffic off the public internet.' },
      gap: missingEndpoints.length === 0 ? undefined : {
        description: 'Calls to these AWS services egress over the internet from the VPC.',
        affected_resources: missingEndpoints.map<AffectedResource>((s) => ({ type: 'aws_vpc_endpoint', identifier: s, name: s, attributes: {} })),
      },
      remediation: missingEndpoints.length === 0 ? undefined : {
        summary: 'Add VPC endpoints for each missing service.',
        options: [{
          approach: 'Add VPC interface/gateway endpoints via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Interface endpoints: per endpoint-hour + GB. Gateway endpoints (S3, DynamoDB) are free.' },
          availability_impact: { level: 'low', notes: 'Additive.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per missing service.' },
          steps: ['Add VPC endpoint per service.', 'Update SG + endpoint policies.', 'Validate.'],
          example_code: `resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-RVP — Reviewing Protections (DoS)
// =====================================================================
export async function collectCnaRvp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { inv, warnings, evidence } = await fetchNetworkInventory(ctx);

  const wafsWithRateRules: string[] = [];
  const waf = aws.wafv2(ctx.auth);
  for (const acl of inv.wafWebAcls) {
    if (!acl.ARN) continue;
    try {
      const detail = await waf.send(new GetWebACLCommand({ Id: acl.Id, Name: acl.Name, Scope: 'REGIONAL' }));
      const rules = detail.WebACL?.Rules ?? [];
      const hasRate = rules.some((r: any) => r.Statement?.RateBasedStatement);
      if (hasRate) wafsWithRateRules.push(acl.Name ?? acl.Id);
      evidence.push(ev('wafv2.GetWebACL', { name: acl.Name, has_rate_based: hasRate, total_rules: rules.length }));
    } catch (e: any) { warnings.push(`GetWebACL ${acl.Name}: ${e.message}`); }
  }

  const publicAlbs = inv.loadBalancers.filter((l: any) => l.Scheme === 'internet-facing');

  const findings = [
    finding({
      rule: 'aws.shield_or_waf_protection_present',
      passed: inv.shieldAdvancedActive || wafsWithRateRules.length >= 1,
      severity: 'high',
      current: {
        summary: inv.shieldAdvancedActive
          ? 'Shield Advanced subscription is active.'
          : (wafsWithRateRules.length >= 1
            ? `${wafsWithRateRules.length} WAF Web ACL(s) with rate-based rules.`
            : 'No Shield Advanced and no rate-based WAF rules detected.'),
        observations: {
          shield_advanced: inv.shieldAdvancedActive,
          wafs_total: inv.wafWebAcls.length,
          wafs_with_rate_rules: wafsWithRateRules,
          public_albs: publicAlbs.length,
        },
      },
      target: { summary: 'DoS protection: Shield Advanced (for high-risk targets), OR WAF rate-based rules on all public ALBs/CloudFront.', rationale: 'NIST SC-5. FedRAMP 20x explicitly requires DoS protection review.' },
      gap: (inv.shieldAdvancedActive || wafsWithRateRules.length >= 1) ? undefined : {
        description: 'No L7 DoS protection detected. Volumetric attacks degrade or take down public endpoints.',
        affected_resources: publicAlbs.map<AffectedResource>((l: any) => ({
          type: 'aws_lb', identifier: l.LoadBalancerArn, name: l.LoadBalancerName, attributes: { scheme: l.Scheme },
        })),
      },
      remediation: (inv.shieldAdvancedActive || wafsWithRateRules.length >= 1) ? undefined : {
        summary: 'Deploy WAFv2 rate-based rules on every public ALB/CloudFront; consider Shield Advanced for high-risk targets.',
        options: [{
          approach: 'WAFv2 Web ACL with rate-based rules attached to each public ALB.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'WAF: ~$5/month/ACL + per-request. Shield Advanced: $3000/month/account + data transfer.' },
          availability_impact: { level: 'low', notes: 'Rules in COUNT mode first to tune; then BLOCK.' },
          customer_visible: { level: 'low', notes: 'Legitimate users may rarely see 403 if hitting rate limits.' },
          effort_estimate: { magnitude: 'weeks', notes: 'ACL setup + observation + tuning.' },
          steps: ['Deploy WAFv2 Web ACL with managed rule groups + rate-based rule.', 'COUNT mode for 2 weeks.', 'Tune false positives.', 'Promote to BLOCK.'],
          example_code: `resource "aws_wafv2_web_acl" "main" {
  name = "main"
  scope = "REGIONAL"
  default_action { allow {} }
  rule {
    name = "rate-limit-all"
    priority = 1
    action { block {} }
    statement {
      rate_based_statement { limit = 2000  aggregate_key_type = "IP" }
    }
    visibility_config { cloudwatch_metrics_enabled = true  metric_name = "rate-limit"  sampled_requests_enabled = true }
  }
  visibility_config { cloudwatch_metrics_enabled = true  metric_name = "main"  sampled_requests_enabled = true }
}
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.public.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}`,
        }],
      },
      alternative_satisfiers: [
        { via: 'CloudFront + 3rd-party CDN (Cloudflare, Akamai, Fastly)', description: 'Front endpoints with a CDN with built-in DoS protection.', evidence_required: ['CDN WAF/rate-limit config', 'recent traffic chart'], detected: false },
      ],
      nist_controls: ['sc-5','sc-5.1','sc-5.2'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-SNT — Securing Network Traffic (TLS posture at the boundary)
// =====================================================================
export async function collectSvcSnt(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { inv, warnings, evidence } = await fetchNetworkInventory(ctx);

  // ELB listeners — TLS posture
  interface ListenerAudit { lb: string; protocol: string; port: number; sslPolicy?: string; }
  const listeners: ListenerAudit[] = [];
  const httpListeners: ListenerAudit[] = [];
  const weakTlsListeners: ListenerAudit[] = [];
  try {
    const elb = aws.elbv2(ctx.auth);
    for (const lb of inv.loadBalancers) {
      if (!lb.LoadBalancerArn) continue;
      try {
        const r = await elb.send(new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }));
        for (const l of r.Listeners ?? []) {
          const a: ListenerAudit = {
            lb: lb.LoadBalancerName ?? '?',
            protocol: l.Protocol ?? '',
            port: l.Port ?? 0,
            sslPolicy: l.SslPolicy,
          };
          listeners.push(a);
          if (l.Protocol === 'HTTP') httpListeners.push(a);
          // TLS 1.0/1.1 in policy name indicates weak TLS
          if (l.SslPolicy && (/TLSv1\.?(0|1)/i.test(l.SslPolicy) || /-2014-/i.test(l.SslPolicy) || /-2015-/i.test(l.SslPolicy))) {
            weakTlsListeners.push(a);
          }
        }
      } catch (e: any) { warnings.push(`DescribeListeners ${lb.LoadBalancerName}: ${e.message}`); }
    }
    evidence.push(ev('elbv2.listener_tls_audit', { total_listeners: listeners.length, http_listeners: httpListeners, weak_tls_listeners: weakTlsListeners }));
  } catch (e: any) { warnings.push(`ELB listener inspection: ${e.message}`); }

  // CloudFront distributions
  interface CfAudit { id: string; domainName: string; viewerProtocolPolicy: string; minTlsVersion?: string; }
  const cfDistributions: CfAudit[] = [];
  const cfWithoutHttpsOnly: CfAudit[] = [];
  const cfWithWeakTls: CfAudit[] = [];
  try {
    const cf = aws.cloudfront(ctx.auth);
    const r = await cf.send(new ListDistributionsCommand({}));
    for (const d of r.DistributionList?.Items ?? []) {
      if (!d.Id) continue;
      try {
        const detail = await cf.send(new GetDistributionCommand({ Id: d.Id }));
        const dist = detail.Distribution;
        const defaultBehavior = dist?.DistributionConfig?.DefaultCacheBehavior;
        const minTls = dist?.DistributionConfig?.ViewerCertificate?.MinimumProtocolVersion;
        const vpp = defaultBehavior?.ViewerProtocolPolicy ?? '';
        const audit: CfAudit = {
          id: d.Id,
          domainName: dist?.DomainName ?? '',
          viewerProtocolPolicy: vpp,
          minTlsVersion: minTls,
        };
        cfDistributions.push(audit);
        if (vpp !== 'redirect-to-https' && vpp !== 'https-only') cfWithoutHttpsOnly.push(audit);
        if (minTls && /TLSv1$|TLSv1_2016|TLSv1\.1/i.test(minTls)) cfWithWeakTls.push(audit);
      } catch (e: any) { warnings.push(`GetDistribution ${d.Id}: ${e.message}`); }
    }
    evidence.push(ev('cloudfront.distribution_tls_audit', { total: cfDistributions.length, without_https_only: cfWithoutHttpsOnly, weak_tls: cfWithWeakTls }));
  } catch (e: any) { warnings.push(`CloudFront: ${e.message}`); }

  const findings = [
    finding({
      rule: 'aws.elb.no_http_listeners_in_prod',
      passed: httpListeners.length === 0,
      severity: 'critical',
      current: {
        summary: httpListeners.length === 0
          ? `No plain-HTTP listeners across ${listeners.length} listener(s).`
          : `${httpListeners.length} HTTP listener(s) found. Inspect: may be HTTP→HTTPS redirect (acceptable) or plain-HTTP traffic (unacceptable).`,
        observations: { http_listeners: httpListeners, all_listeners: listeners },
      },
      target: { summary: 'No plain-HTTP listeners on prod ALBs/NLBs except those that immediately redirect to HTTPS.', rationale: 'NIST SC-8, SC-8.1. TLS for federal customer data.' },
      gap: httpListeners.length === 0 ? undefined : {
        description: 'HTTP listeners may transmit data in cleartext.',
        affected_resources: httpListeners.map<AffectedResource>((h) => ({
          type: 'aws_lb_listener', identifier: `${h.lb}:${h.port}`, name: h.lb, attributes: { port: h.port, protocol: h.protocol },
        })),
      },
      remediation: httpListeners.length === 0 ? undefined : {
        summary: 'Convert HTTP listeners to redirect-only OR remove. Use HTTPS listeners with TLS 1.2+ SSL policy.',
        options: [{
          approach: 'Configure HTTP→HTTPS redirect via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Clients using HTTP must follow redirects.' },
          customer_visible: { level: 'medium', notes: 'HTTP clients see 301 redirects.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per listener.' },
          steps: ['Replace plain HTTP listener with redirect-action.', 'Apply.'],
          example_code: `resource "aws_lb_listener" "redirect" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect { port = "443" protocol = "HTTPS" status_code = "HTTP_301" }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8','sc-8.1'],
    }),

    finding({
      rule: 'aws.elb.ssl_policy_tls_1_2_or_higher',
      passed: weakTlsListeners.length === 0,
      severity: 'high',
      current: {
        summary: weakTlsListeners.length === 0
          ? 'No listener uses a weak SSL policy (TLS 1.0/1.1 / 2014-2015 era).'
          : `${weakTlsListeners.length} listener(s) use a weak SSL policy.`,
        observations: { weak_tls_listeners: weakTlsListeners },
      },
      target: { summary: 'All HTTPS listeners use SSL policies enforcing TLS 1.2+ (preferably TLS 1.3): e.g. ELBSecurityPolicy-TLS13-1-2-2021-06.', rationale: 'NIST SC-8.1. TLS 1.0/1.1 are deprecated.' },
      gap: weakTlsListeners.length === 0 ? undefined : {
        description: 'Weak TLS allows downgrade attacks.',
        affected_resources: weakTlsListeners.map<AffectedResource>((l) => ({
          type: 'aws_lb_listener', identifier: `${l.lb}:${l.port}`, name: l.lb, attributes: { ssl_policy: l.sslPolicy },
        })),
      },
      remediation: weakTlsListeners.length === 0 ? undefined : {
        summary: 'Update ssl_policy to a TLS 1.2+ policy via Terraform.',
        options: [{
          approach: 'Update ssl_policy.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Very old clients (Windows XP era) may break — verify customer baseline.' },
          customer_visible: { level: 'low', notes: 'Clients using TLS 1.0/1.1 lose access.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Set ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06" (or stricter).', 'Apply.'],
          example_code: `resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}`,
          references: [{ title: 'ELB SSL policies', url: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8','sc-8.1'],
    }),

    finding({
      rule: 'aws.cloudfront.viewer_protocol_https_only',
      passed: cfWithoutHttpsOnly.length === 0,
      severity: 'high',
      current: {
        summary: cfWithoutHttpsOnly.length === 0
          ? `${cfDistributions.length} CloudFront distribution(s); all enforce HTTPS-only or redirect.`
          : `${cfWithoutHttpsOnly.length} CloudFront distribution(s) allow plain-HTTP viewer access.`,
        observations: { distributions: cfDistributions, without_https_only: cfWithoutHttpsOnly },
      },
      target: { summary: 'All CloudFront distributions have ViewerProtocolPolicy = redirect-to-https or https-only AND MinimumProtocolVersion >= TLSv1.2_2021.', rationale: 'NIST SC-8.' },
      gap: cfWithoutHttpsOnly.length === 0 ? undefined : {
        description: 'Plain-HTTP CloudFront viewer policy.',
        affected_resources: cfWithoutHttpsOnly.map<AffectedResource>((c) => ({
          type: 'aws_cloudfront_distribution', identifier: c.id, name: c.domainName, attributes: { viewer_protocol_policy: c.viewerProtocolPolicy },
        })),
      },
      remediation: cfWithoutHttpsOnly.length === 0 ? undefined : {
        summary: 'Set viewer_protocol_policy = "redirect-to-https" via Terraform.',
        options: [{
          approach: 'Update distribution config.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'HTTP viewers redirect.' },
          customer_visible: { level: 'low', notes: 'HTTP→HTTPS redirect.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per distribution.' },
          steps: ['Set viewer_protocol_policy.', 'Set minimum_protocol_version=TLSv1.2_2021.', 'Apply.'],
          example_code: `resource "aws_cloudfront_distribution" "main" {
  default_cache_behavior { viewer_protocol_policy = "redirect-to-https" }
  viewer_certificate    { minimum_protocol_version = "TLSv1.2_2021" }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8','sc-8.1'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}
