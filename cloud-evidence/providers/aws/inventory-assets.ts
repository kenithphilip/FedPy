/**
 * AWS asset enumeration for the FedRAMP Integrated Inventory Workbook.
 *
 * Read-only: enumerates resources across a curated set of high-value services and
 * normalizes them to `CloudAsset` rows for `core/inventory-workbook.ts`. This is
 * distinct from `inventory.ts` (KSI-PIY-GIV), which only checks that an inventory
 * *mechanism* exists; here we produce the actual asset list.
 *
 * Field mapping is clean-room, informed by the Apache-2.0 reference design
 * `aws-samples/fedramp-integrated-inventory-workbook` (see research report 06 /
 * the licensing decision in research/reports/00-INDEX.md — NOT the GPL-3.0
 * `manywho/awsinventory`).
 *
 * Every SDK client comes from `core/auth/aws.ts`, which wraps it in the
 * read-only guardrail, so no mutating call is possible from here.
 */
import { DescribeInstancesCommand, DescribeVolumesCommand, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { DescribeDBInstancesCommand, DescribeDBSnapshotsCommand, DescribeDBParametersCommand, DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { ListBucketsCommand, GetBucketLocationCommand, GetPublicAccessBlockCommand, GetBucketEncryptionCommand } from '@aws-sdk/client-s3';
import { GetInventoryCommand, DescribeInstancePatchStatesCommand } from '@aws-sdk/client-ssm';
import { ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { DescribeLoadBalancersCommand, DescribeListenersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ListTablesCommand, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { DescribeRepositoriesCommand } from '@aws-sdk/client-ecr';
import { ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import { ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import * as aws from '../../core/auth/aws.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';
import { isFipsTlsPolicy } from './crypto.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

export interface AwsAssetResult { assets: CloudAsset[]; warnings: string[]; }

type AwsTag = { Key?: string; Value?: string };
function tag(tags: AwsTag[] | undefined, key: string): string | undefined {
  return tags?.find((t) => (t.Key ?? '').toLowerCase() === key.toLowerCase())?.Value || undefined;
}
/** AWS `[{Key,Value}]` tag list → plain record for tag-driven enrichment. */
function tagsToRecord(tags: AwsTag[] | undefined): Record<string, string> | undefined {
  if (!tags || tags.length === 0) return undefined;
  const r: Record<string, string> = {};
  for (const t of tags) if (t.Key) r[t.Key] = t.Value ?? '';
  return r;
}

/**
 * Infer the container-host OS family from an EC2 platform/AMI hint. Bottlerocket
 * matters for Prisma Defender (DaemonSet + specific config vs a host package).
 */
export function nodeOsFamilyFromHint(platformDetails: string | null | undefined, amiName?: string | null): string | null {
  const h = `${platformDetails ?? ''} ${amiName ?? ''}`.toLowerCase();
  if (!h.trim()) return null;
  if (/bottlerocket/.test(h)) return 'Bottlerocket';
  if (/amazon linux 2023|al2023/.test(h)) return 'Amazon Linux 2023';
  if (/amazon linux 2|amzn2|al2/.test(h)) return 'Amazon Linux 2';
  if (/windows/.test(h)) return 'Windows';
  if (/ubuntu/.test(h)) return 'Ubuntu';
  if (/red hat|rhel/.test(h)) return 'RHEL';
  return null;
}

/** Node-analysis facts derived from an EC2 instance's tags (EKS / Karpenter). */
export function deriveNodeFacts(tags: Record<string, string> | undefined): {
  k8sCluster: string | null; nodeGroup: string | null; karpenterNodePool: string | null; fipsTagged: boolean | null;
} {
  if (!tags) return { k8sCluster: null, nodeGroup: null, karpenterNodePool: null, fipsTagged: null };
  // Treat empty-string tag values as absent (an empty nodegroup tag must not win
  // over the Karpenter nodepool).
  const lower = new Map(Object.entries(tags).map(([k, v]) => [k.toLowerCase(), v?.trim() ? v.trim() : undefined]));
  const g = (k: string): string | undefined => lower.get(k) || undefined;
  let cluster = g('eks:cluster-name') ?? g('eks:eks-cluster-name') ?? g('aws:eks:cluster-name') ?? null;
  if (!cluster) for (const [k] of lower) { const m = /^kubernetes\.io\/cluster\/(.+)$/.exec(k); if (m) { cluster = m[1]!; break; } }
  const nodePool = g('karpenter.sh/nodepool') ?? null;
  const nodeGroup = g('eks:nodegroup-name') ?? g('aws:eks:nodegroup-name') ?? nodePool ?? null;
  const fipsRaw = lower.get('fipscompliant') ?? lower.get('fips') ?? null;
  const fipsTagged = fipsRaw == null ? null : /^(true|yes|enabled|1)$/i.test(fipsRaw);
  return { k8sCluster: cluster, nodeGroup, karpenterNodePool: nodePool, fipsTagged };
}

/**
 * Enumerate AWS assets in one region and normalize them. Global services (S3,
 * CloudFront) are only enumerated when `includeGlobal` (default true) so a
 * multi-region sweep can collect them exactly once.
 */
export async function collectAwsAssets(
  auth: aws.AwsAuth,
  account: string | null,
  opts: { includeGlobal?: boolean } = {},
): Promise<AwsAssetResult> {
  const includeGlobal = opts.includeGlobal ?? true;
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  const region = auth.region;
  // Partition-aware ARN synthesis so ids match the account's real ARNs (GovCloud
  // = aws-us-gov, China = aws-cn) — otherwise dedup fails and assets duplicate.
  const partition = aws.awsPartition(region);
  const arn = (svc: string, resource: string) => `arn:${partition}:${svc}:${region}:${account ?? ''}:${resource}`;

  // Network exposure (INV-15): map security-group id → ports open to the internet
  // (ingress from 0.0.0.0/0 or ::/0). Used to populate each instance's openPorts.
  const sgOpenPorts = new Map<string, string[]>();
  try {
    const ec2 = aws.ec2(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await ec2.send(new DescribeSecurityGroupsCommand({ NextToken: token, MaxResults: 200 }));
      for (const sg of r.SecurityGroups ?? []) {
        if (!sg.GroupId) continue;
        const open: string[] = [];
        for (const p of sg.IpPermissions ?? []) {
          const anyV4 = (p.IpRanges ?? []).some((r2) => r2.CidrIp === '0.0.0.0/0');
          const anyV6 = (p.Ipv6Ranges ?? []).some((r2) => r2.CidrIpv6 === '::/0');
          if (!anyV4 && !anyV6) continue;
          const proto = p.IpProtocol === '-1' ? 'all' : (p.IpProtocol ?? 'tcp');
          const range = p.FromPort == null ? 'all' : (p.FromPort === p.ToPort ? `${p.FromPort}` : `${p.FromPort}-${p.ToPort}`);
          open.push(`${proto}/${range}`);
        }
        if (open.length) sgOpenPorts.set(sg.GroupId, [...new Set(open)]);
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`Security groups (ec2:DescribeSecurityGroups): ${e.message}`); }

  // EC2 instances — IPs + MACs come straight from the NetworkInterfaces field.
  try {
    const ec2 = aws.ec2(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await ec2.send(new DescribeInstancesCommand({ NextToken: token, MaxResults: 200 }));
      for (const res of r.Reservations ?? []) {
        for (const inst of res.Instances ?? []) {
          if (!inst.InstanceId) continue;
          const ips: string[] = []; const macs: string[] = [];
          const sgIds = new Set<string>();
          for (const g of inst.SecurityGroups ?? []) if (g.GroupId) sgIds.add(g.GroupId);
          for (const ni of inst.NetworkInterfaces ?? []) {
            for (const g of ni.Groups ?? []) if (g.GroupId) sgIds.add(g.GroupId);
            for (const pip of ni.PrivateIpAddresses ?? []) {
              if (pip.PrivateIpAddress) { ips.push(pip.PrivateIpAddress); macs.push(ni.MacAddress ?? ''); }
              if (pip.Association?.PublicIp) { ips.push(pip.Association.PublicIp); macs.push(ni.MacAddress ?? ''); }
            }
          }
          const openPorts = [...new Set([...sgIds].flatMap((id) => sgOpenPorts.get(id) ?? []))];
          const instTags = tagsToRecord(inst.Tags);
          const nodeFacts = deriveNodeFacts(instTags);
          assets.push({
            provider: 'aws',
            uniqueId: arn('ec2', `instance/${inst.InstanceId}`),
            resourceType: 'AWS::EC2::Instance',
            ips,
            macs,
            openPorts: openPorts.length ? openPorts : undefined,
            virtual: true,
            publicFacing: Boolean(inst.PublicIpAddress),
            dns: inst.PublicDnsName || inst.PrivateDnsName || null,
            osNameVersion: inst.PlatformDetails ?? (inst.Platform ?? null),
            location: inst.Placement?.AvailabilityZone ?? region,
            assetType: 'Compute Instance',
            hardwareMakeModel: `AWS EC2 ${inst.InstanceType ?? ''}`.trim(),
            imageId: inst.ImageId ?? null,
            architecture: inst.Architecture ?? null,
            state: inst.State?.Name ?? null,
            createdAt: inst.LaunchTime ? new Date(inst.LaunchTime).toISOString() : null,
            vlanNetworkId: [inst.VpcId, inst.SubnetId].filter(Boolean).join('/') || null,
            tags: instTags,
            // Node analysis (Prisma Defender planning).
            k8sCluster: nodeFacts.k8sCluster,
            nodeGroup: nodeFacts.nodeGroup,
            karpenterNodePool: nodeFacts.karpenterNodePool,
            fipsTagged: nodeFacts.fipsTagged,
            nodeOsFamily: nodeOsFamilyFromHint(inst.PlatformDetails),
          });
        }
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`EC2 instances (ec2:DescribeInstances): ${e.message}`); }

  // EBS volumes
  try {
    const ec2 = aws.ec2(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await ec2.send(new DescribeVolumesCommand({ NextToken: token, MaxResults: 200 }));
      for (const v of r.Volumes ?? []) {
        if (!v.VolumeId) continue;
        // Attachment(s) → drive the volume→instance edge in deriveEdges. The ARN
        // is synthesized to match the EC2 instance uniqueId format above.
        const attachedInstanceArns = (v.Attachments ?? [])
          .map((att) => att.InstanceId)
          .filter((id): id is string => !!id)
          .map((id) => arn('ec2', `instance/${id}`));
        assets.push({
          provider: 'aws',
          uniqueId: arn('ec2', `volume/${v.VolumeId}`),
          resourceType: 'AWS::EC2::Volume',
          virtual: true,
          location: v.AvailabilityZone ?? region,
          assetType: 'Storage Volume',
          hardwareMakeModel: `AWS EBS ${v.VolumeType ?? ''}`.trim(),
          sizeGb: v.Size ?? null,
          state: v.State ?? null,
          createdAt: v.CreateTime ? new Date(v.CreateTime).toISOString() : null,
          encryptionAtRest: v.Encrypted ?? null,
          kmsKeyId: v.KmsKeyId ?? null,
          tags: tagsToRecord(v.Tags),
          comments: v.Encrypted ? 'Encrypted' : 'Not encrypted',
          // Consumed by deriveEdges to emit `attached-to` volume→instance edges.
          raw: attachedInstanceArns.length ? { attachedInstanceArns } : undefined,
        });
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`EBS volumes (ec2:DescribeVolumes): ${e.message}`); }

  // RDS instances (+ in-transit posture via parameter-group force-SSL).
  try {
    const rds = aws.rds(auth);
    // Cache force-SSL per parameter-group so we resolve each group at most once.
    const forceSslByGroup = new Map<string, boolean | null>();
    const resolveForceSsl = async (groupName: string, engine: string): Promise<boolean | null> => {
      if (forceSslByGroup.has(groupName)) return forceSslByGroup.get(groupName)!;
      // Which parameter enforces TLS depends on the engine family.
      const paramName = /mysql|maria|aurora-mysql|aurora$/i.test(engine) ? 'require_secure_transport' : 'rds.force_ssl';
      let result: boolean | null = null;
      try {
        let pmarker: string | undefined; let ppages = 0;
        do {
          const pr = await rds.send(new DescribeDBParametersCommand({ DBParameterGroupName: groupName, Marker: pmarker, MaxRecords: 100 }));
          const hit = (pr.Parameters ?? []).find((p) => p.ParameterName === paramName);
          if (hit) { result = /^(1|on|true)$/i.test(hit.ParameterValue ?? ''); break; }
          pmarker = pr.Marker && pr.Marker !== pmarker ? pr.Marker : undefined;
        } while (pmarker && ++ppages < MAX_PAGES);
      } catch (e: any) { warnings.push(diagnoseAwsError(e, `rds.DescribeDBParameters ${groupName}`, 'rds:DescribeDBParameters')); }
      forceSslByGroup.set(groupName, result);
      return result;
    };
    let marker: string | undefined; let pages = 0;
    do {
      const r = await rds.send(new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }));
      for (const db of r.DBInstances ?? []) {
        if (!db.DBInstanceIdentifier) continue;
        // In-transit: resolve force-SSL from the instance's (in-sync) parameter group.
        const pg = (db.DBParameterGroups ?? []).find((g) => g.ParameterApplyStatus === 'in-sync') ?? db.DBParameterGroups?.[0];
        let encryptionInTransit: boolean | null = null;
        if (pg?.DBParameterGroupName) encryptionInTransit = await resolveForceSsl(pg.DBParameterGroupName, db.Engine ?? '');
        assets.push({
          provider: 'aws',
          uniqueId: db.DBInstanceArn ?? arn('rds', `db:${db.DBInstanceIdentifier}`),
          resourceType: 'AWS::RDS::DBInstance',
          ips: db.Endpoint?.Address ? [db.Endpoint.Address] : undefined,
          virtual: true,
          publicFacing: Boolean(db.PubliclyAccessible),
          dns: db.Endpoint?.Address ?? null,
          location: db.AvailabilityZone ?? region,
          assetType: 'Database',
          softwareDatabaseVendor: db.Engine ?? null,
          softwareDatabaseNameVersion: [db.Engine, db.EngineVersion].filter(Boolean).join(' ') || null,
          hardwareMakeModel: db.DBInstanceClass ? `AWS RDS ${db.DBInstanceClass}${db.MultiAZ ? ' (Multi-AZ)' : ''}` : null,
          sizeGb: db.AllocatedStorage ?? null,
          state: db.DBInstanceStatus ?? null,
          createdAt: db.InstanceCreateTime ? new Date(db.InstanceCreateTime).toISOString() : null,
          encryptionAtRest: db.StorageEncrypted ?? null,
          encryptionInTransit,
          kmsKeyId: db.KmsKeyId ?? null,
          vlanNetworkId: db.DBSubnetGroup?.VpcId ?? null,
        });
      }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'rds.DescribeDBInstances', 'rds:DescribeDBInstances')); }

  // RDS snapshots — encryption posture (SC-28). Manual snapshots only by default;
  // the Config backbone sees them but not their `Encrypted` flag.
  try {
    const rds = aws.rds(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await rds.send(new DescribeDBSnapshotsCommand({ Marker: marker, MaxRecords: 100 }));
      for (const snap of r.DBSnapshots ?? []) {
        if (!snap.DBSnapshotArn && !snap.DBSnapshotIdentifier) continue;
        assets.push({
          provider: 'aws',
          uniqueId: snap.DBSnapshotArn ?? arn('rds', `snapshot:${snap.DBSnapshotIdentifier}`),
          resourceType: 'AWS::RDS::DBSnapshot',
          virtual: true,
          location: snap.AvailabilityZone ?? region,
          assetType: 'Database Snapshot',
          softwareDatabaseVendor: snap.Engine ?? null,
          softwareDatabaseNameVersion: [snap.Engine, snap.EngineVersion].filter(Boolean).join(' ') || null,
          state: snap.Status ?? null,
          createdAt: snap.SnapshotCreateTime ? new Date(snap.SnapshotCreateTime).toISOString() : null,
          encryptionAtRest: snap.Encrypted ?? null,
          kmsKeyId: snap.KmsKeyId ?? null,
          sizeGb: snap.AllocatedStorage ?? null,
          function: snap.DBSnapshotIdentifier ?? null,
        });
      }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'rds.DescribeDBSnapshots', 'rds:DescribeDBSnapshots')); }

  // S3 buckets (account-global — collected once when includeGlobal)
  if (includeGlobal) try {
    const s3 = aws.s3(auth);
    const r = await s3.send(new ListBucketsCommand({}));
    for (const b of r.Buckets ?? []) {
      if (!b.Name) continue;
      let loc: string | null = null;
      try {
        const l = await s3.send(new GetBucketLocationCommand({ Bucket: b.Name }));
        loc = (l.LocationConstraint as string) || 'us-east-1';
      } catch { /* keep null on per-bucket error */ }
      // Public-exposure (col E): if a Public Access Block is fully on, not public.
      let publicFacing: boolean | undefined;
      try {
        const pab = await s3.send(new GetPublicAccessBlockCommand({ Bucket: b.Name }));
        const c = pab.PublicAccessBlockConfiguration;
        const fullyBlocked = Boolean(c?.BlockPublicAcls && c?.BlockPublicPolicy && c?.IgnorePublicAcls && c?.RestrictPublicBuckets);
        publicFacing = !fullyBlocked;
      } catch { /* no PAB config / no perm → leave unknown */ }
      // Encryption at rest (+ KMS key) from the default encryption config.
      let encryptionAtRest: boolean | undefined; let kmsKeyId: string | null = null;
      try {
        const enc = await s3.send(new GetBucketEncryptionCommand({ Bucket: b.Name }));
        const rule = enc.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault;
        encryptionAtRest = Boolean(rule);
        kmsKeyId = rule?.KMSMasterKeyID ?? null;
      } catch { /* none / no perm */ }
      assets.push({
        provider: 'aws',
        uniqueId: `arn:${partition}:s3:::${b.Name}`,
        resourceType: 'AWS::S3::Bucket',
        virtual: true,
        publicFacing,
        location: loc,
        assetType: 'Object Storage Bucket',
        createdAt: b.CreationDate ? new Date(b.CreationDate).toISOString() : null,
        encryptionAtRest,
        kmsKeyId,
        function: b.Name,
      });
    }
  } catch (e: any) { warnings.push(`S3 buckets (s3:ListAllMyBuckets): ${e.message}`); }

  // Lambda functions
  try {
    const lambda = aws.lambda(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await lambda.send(new ListFunctionsCommand({ Marker: marker, MaxItems: 50 }));
      for (const fn of r.Functions ?? []) {
        if (!fn.FunctionName) continue;
        assets.push({
          provider: 'aws',
          uniqueId: fn.FunctionArn ?? arn('lambda', `function:${fn.FunctionName}`),
          resourceType: 'AWS::Lambda::Function',
          virtual: true,
          location: region,
          assetType: 'Serverless Function',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: fn.Runtime ?? null,
          // ListFunctions already returns these — harvest rather than drop them.
          memoryMb: fn.MemorySize ?? null,
          architecture: fn.Architectures?.[0] ?? null,
          lastModifiedAt: fn.LastModified ? new Date(fn.LastModified).toISOString() : null,
          vlanNetworkId: fn.VpcConfig?.VpcId ?? null,
          function: fn.FunctionName,
        });
      }
      marker = r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`Lambda functions (lambda:ListFunctions): ${e.message}`); }

  // ELBv2 load balancers (ALB/NLB/GLB) + their HTTPS/TLS listener policy (FIPS).
  try {
    const elbv2 = aws.elbv2(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await elbv2.send(new DescribeLoadBalancersCommand({ Marker: marker, PageSize: 100 }));
      for (const lb of r.LoadBalancers ?? []) {
        if (!lb.LoadBalancerArn) continue;
        // Fetch listeners to surface the TLS/SSL policy (in-transit + FIPS posture).
        let tlsPolicy: string | null = null;
        let encryptionInTransit: boolean | null = null;
        try {
          const ls = await elbv2.send(new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }));
          const tlsListeners = (ls.Listeners ?? []).filter((l) => l.Protocol === 'HTTPS' || l.Protocol === 'TLS');
          if (tlsListeners.length) {
            encryptionInTransit = true;
            // Prefer a FIPS policy name if any listener uses one; else the first policy.
            tlsPolicy = tlsListeners.find((l) => isFipsTlsPolicy(l.SslPolicy))?.SslPolicy
              ?? tlsListeners[0]!.SslPolicy ?? null;
          } else if ((ls.Listeners ?? []).length) {
            encryptionInTransit = false; // listeners exist but none terminate TLS (ALB); NLB may pass through
          }
        } catch (e: any) { warnings.push(diagnoseAwsError(e, `elbv2.DescribeListeners ${lb.LoadBalancerName}`, 'elasticloadbalancing:DescribeListeners')); }
        assets.push({
          provider: 'aws',
          uniqueId: lb.LoadBalancerArn,
          resourceType: `AWS::ElasticLoadBalancingV2::${lb.Type === 'network' ? 'NetworkLoadBalancer' : lb.Type === 'gateway' ? 'GatewayLoadBalancer' : 'LoadBalancer'}`,
          virtual: true,
          publicFacing: lb.Scheme === 'internet-facing',
          dns: lb.DNSName ?? null,
          location: region,
          assetType: 'Load Balancer',
          hardwareMakeModel: `AWS ELB ${lb.Type ?? ''}`.trim(),
          state: lb.State?.Code ?? null,
          createdAt: lb.CreatedTime ? new Date(lb.CreatedTime).toISOString() : null,
          vlanNetworkId: lb.VpcId ?? null,
          function: lb.LoadBalancerName ?? null,
          encryptionInTransit,
          tlsPolicy,
          fipsTlsPolicy: tlsPolicy ? isFipsTlsPolicy(tlsPolicy) : null,
        });
      }
      marker = r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'elbv2.DescribeLoadBalancers', 'elasticloadbalancing:DescribeLoadBalancers')); }

  // DynamoDB tables
  try {
    const ddb = aws.dynamodb(auth);
    let start: string | undefined; let pages = 0;
    do {
      const r = await ddb.send(new ListTablesCommand({ ExclusiveStartTableName: start, Limit: 100 }));
      for (const name of r.TableNames ?? []) {
        // DescribeTable is already called for the ARN — harvest the rest of its
        // response (size / status / created / SSE) instead of dropping it.
        let dArn: string | undefined; let sizeGb: number | null = null;
        let state: string | null = null; let createdAt: string | null = null;
        let encryptionAtRest: boolean | undefined; let kmsKeyId: string | null = null;
        try {
          const d = await ddb.send(new DescribeTableCommand({ TableName: name }));
          const t = d.Table;
          dArn = t?.TableArn;
          if (t?.TableSizeBytes != null) sizeGb = Math.round((t.TableSizeBytes / 1_073_741_824) * 1000) / 1000;
          state = t?.TableStatus ?? null;
          createdAt = t?.CreationDateTime ? new Date(t.CreationDateTime).toISOString() : null;
          // SSEDescription present + ENABLED/UPDATING ⇒ KMS/AWS-owned encryption on.
          if (t?.SSEDescription?.Status) {
            encryptionAtRest = t.SSEDescription.Status === 'ENABLED' || t.SSEDescription.Status === 'UPDATING';
            kmsKeyId = t.SSEDescription.KMSMasterKeyArn ?? null;
          } else {
            encryptionAtRest = true; // DynamoDB is always encrypted at rest (AWS-owned key by default)
          }
        } catch { /* keep nulls */ }
        assets.push({
          provider: 'aws',
          uniqueId: dArn ?? arn('dynamodb', `table/${name}`),
          resourceType: 'AWS::DynamoDB::Table',
          virtual: true,
          location: region,
          assetType: 'Database',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: 'Amazon DynamoDB',
          sizeGb,
          state,
          createdAt,
          encryptionAtRest,
          kmsKeyId,
          function: name,
        });
      }
      start = r.LastEvaluatedTableName && r.LastEvaluatedTableName !== start ? r.LastEvaluatedTableName : undefined;
    } while (start && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`DynamoDB (dynamodb:ListTables): ${e.message}`); }

  // ECR repositories
  try {
    const ecr = aws.ecr(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await ecr.send(new DescribeRepositoriesCommand({ nextToken: token, maxResults: 100 }));
      for (const repo of r.repositories ?? []) {
        if (!repo.repositoryArn) continue;
        assets.push({
          provider: 'aws',
          uniqueId: repo.repositoryArn,
          resourceType: 'AWS::ECR::Repository',
          virtual: true,
          dns: repo.repositoryUri ?? null,
          location: region,
          assetType: 'Container Registry',
          createdAt: repo.createdAt ? new Date(repo.createdAt).toISOString() : null,
          // Image scanning + at-rest encryption are on the repo record already.
          encryptionAtRest: repo.encryptionConfiguration?.encryptionType ? true : undefined,
          kmsKeyId: repo.encryptionConfiguration?.kmsKey ?? null,
          function: repo.repositoryName ?? null,
        });
      }
      token = r.nextToken && r.nextToken !== token ? r.nextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`ECR (ecr:DescribeRepositories): ${e.message}`); }

  // EKS clusters
  try {
    const eks = aws.eks(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await eks.send(new ListClustersCommand({ nextToken: token, maxResults: 100 }));
      for (const name of r.clusters ?? []) {
        // DescribeCluster is already called — harvest status/created/publicness too.
        let version: string | null = null; let cArn: string | undefined; let cVpc: string | null = null; let endpoint: string | null = null;
        let state: string | null = null; let createdAt: string | null = null;
        let publicFacing: boolean | undefined; let clusterTags: Record<string, string> | undefined;
        let secretsEncrypted: boolean | undefined; let eksKmsKey: string | null = null;
        try {
          const d = await eks.send(new DescribeClusterCommand({ name }));
          version = d.cluster?.version ?? null; cArn = d.cluster?.arn;
          cVpc = d.cluster?.resourcesVpcConfig?.vpcId ?? null; endpoint = d.cluster?.endpoint ?? null;
          state = d.cluster?.status ?? null;
          createdAt = d.cluster?.createdAt ? new Date(d.cluster.createdAt).toISOString() : null;
          publicFacing = d.cluster?.resourcesVpcConfig?.endpointPublicAccess ?? undefined;
          // Envelope (secrets) encryption — already in the DescribeCluster response.
          const encCfg = d.cluster?.encryptionConfig ?? [];
          if (encCfg.length) {
            secretsEncrypted = encCfg.some((e) => (e.resources ?? []).includes('secrets'));
            eksKmsKey = encCfg[0]?.provider?.keyArn ?? null;
          } else {
            secretsEncrypted = false; // no envelope-encryption config on the cluster
          }
          const t = d.cluster?.tags;
          if (t && Object.keys(t).length) clusterTags = { ...t };
        } catch { /* keep nulls */ }
        assets.push({
          provider: 'aws',
          uniqueId: cArn ?? arn('eks', `cluster/${name}`),
          resourceType: 'AWS::EKS::Cluster',
          virtual: true,
          publicFacing,
          dns: endpoint,
          location: region,
          assetType: 'Kubernetes Cluster',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: version ? `Amazon EKS ${version}` : 'Amazon EKS',
          state,
          createdAt,
          vlanNetworkId: cVpc,
          tags: clusterTags,
          function: name,
          encryptionAtRest: secretsEncrypted,   // EKS secrets envelope encryption (KMS)
          kmsKeyId: eksKmsKey,
        });
      }
      token = r.nextToken && r.nextToken !== token ? r.nextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`EKS (eks:ListClusters): ${e.message}`); }

  // CloudFront distributions (account-global — collected once when includeGlobal)
  if (includeGlobal) try {
    const cf = aws.cloudfront(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await cf.send(new ListDistributionsCommand({ Marker: marker, MaxItems: 100 }));
      for (const d of r.DistributionList?.Items ?? []) {
        if (!d.ARN) continue;
        assets.push({
          provider: 'aws',
          uniqueId: d.ARN,
          resourceType: 'AWS::CloudFront::Distribution',
          virtual: true,
          publicFacing: true, // CloudFront distributions are internet-facing CDN edges
          dns: d.DomainName ?? null,
          location: 'global',
          assetType: 'CDN Distribution',
          state: d.Status ?? null,
          function: d.Comment || d.Id || null,
        });
      }
      marker = r.DistributionList?.NextMarker && r.DistributionList.NextMarker !== marker ? r.DistributionList.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`CloudFront (cloudfront:ListDistributions): ${e.message}`); }

  // SSM Inventory (INV-12): enrich EC2 instances with real OS name/version + the
  // Windows guest hostname (NetBIOS Name, column F) from managed-instance
  // information — the API-reported OS is richer than PlatformDetails.
  try {
    const ssm = aws.ssm(auth);
    const osById = new Map<string, string>();
    const netbiosById = new Map<string, string>();
    let token: string | undefined; let pages = 0;
    do {
      const r = await ssm.send(new GetInventoryCommand({ NextToken: token, MaxResults: 50 }));
      for (const ent of r.Entities ?? []) {
        const content = ent.Data?.['AWS:InstanceInformation']?.Content?.[0];
        if (ent.Id && content) {
          const os = [content.PlatformName, content.PlatformVersion].filter(Boolean).join(' ');
          if (os) osById.set(ent.Id, os);
          // ComputerName is the guest hostname; the FedRAMP workbook uses it as the
          // NetBIOS Name for Windows hosts. Populate for Windows only (Linux has no
          // NetBIOS concept — CloudAsset doc), matched by PlatformType.
          const isWindows = (content.PlatformType ?? '').toLowerCase().includes('windows');
          if (isWindows && content.ComputerName) netbiosById.set(ent.Id, content.ComputerName);
        }
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
    if (osById.size || netbiosById.size) {
      for (const a of assets) {
        if (a.resourceType !== 'AWS::EC2::Instance') continue;
        const id = a.uniqueId.split('/').pop();
        if (!id) continue;
        const os = osById.get(id);
        if (os) {
          a.osNameVersion = os; // SSM-reported OS is authoritative over PlatformDetails
          a.nodeOsFamily = nodeOsFamilyFromHint(os) ?? a.nodeOsFamily; // e.g. "Bottlerocket 1.62.1" → Bottlerocket
        }
        const nb = netbiosById.get(id);
        if (nb) a.netbiosName = nb;
      }
    }
  } catch (e: any) { warnings.push(`SSM Inventory (ssm:GetInventory): ${e.message}`); }

  // SSM Patch Manager (INV-12): patch-compliance summary per managed instance →
  // the Patch Level column. Read-only DescribeInstancePatchStates over the EC2
  // instance ids we discovered (batched; the API accepts up to 50 ids/call).
  try {
    const instanceIds = assets
      .filter((a) => a.resourceType === 'AWS::EC2::Instance')
      .map((a) => a.uniqueId.split('/').pop())
      .filter((id): id is string => !!id);
    if (instanceIds.length) {
      const ssm = aws.ssm(auth);
      const patchById = new Map<string, string>();
      for (let i = 0; i < instanceIds.length; i += 50) {
        const batch = instanceIds.slice(i, i + 50);
        try {
          const r = await ssm.send(new DescribeInstancePatchStatesCommand({ InstanceIds: batch }));
          for (const st of r.InstancePatchStates ?? []) {
            if (!st.InstanceId) continue;
            const missing = st.MissingCount ?? 0;
            const failed = st.FailedCount ?? 0;
            const installed = st.InstalledCount ?? 0;
            // "Current" when nothing is missing/failed; else surface the counts.
            patchById.set(
              st.InstanceId,
              missing === 0 && failed === 0
                ? `Current (${installed} installed)`
                : `${missing} missing${failed ? `, ${failed} failed` : ''} (${installed} installed)`,
            );
          }
        } catch { /* batch-level failure is non-fatal; other batches still fill */ }
      }
      if (patchById.size) {
        for (const a of assets) {
          if (a.resourceType !== 'AWS::EC2::Instance') continue;
          const id = a.uniqueId.split('/').pop();
          const pl = id ? patchById.get(id) : undefined;
          if (pl) a.patchLevel = pl;
        }
      }
    }
  } catch (e: any) { warnings.push(`SSM Patch Manager (ssm:DescribeInstancePatchStates): ${e.message}`); }

  // Stamp common provenance on every asset (account / collected-at / source).
  const now = new Date().toISOString();
  for (const a of assets) {
    a.accountId ??= account;
    a.collectedAt ??= now;
    a.sourceApi ??= 'aws-sdk';
  }

  return { assets, warnings };
}
