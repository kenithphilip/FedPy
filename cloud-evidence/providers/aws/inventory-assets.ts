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
import { DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { ListBucketsCommand, GetBucketLocationCommand, GetPublicAccessBlockCommand, GetBucketEncryptionCommand } from '@aws-sdk/client-s3';
import { GetInventoryCommand } from '@aws-sdk/client-ssm';
import { ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { DescribeLoadBalancersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ListTablesCommand, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { DescribeRepositoriesCommand } from '@aws-sdk/client-ecr';
import { ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import { ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import * as aws from '../../core/auth/aws.ts';
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
  const arn = (svc: string, resource: string) => `arn:aws:${svc}:${region}:${account ?? ''}:${resource}`;

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
            tags: tagsToRecord(inst.Tags),
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
        });
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`EBS volumes (ec2:DescribeVolumes): ${e.message}`); }

  // RDS instances
  try {
    const rds = aws.rds(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await rds.send(new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }));
      for (const db of r.DBInstances ?? []) {
        if (!db.DBInstanceIdentifier) continue;
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
          sizeGb: db.AllocatedStorage ?? null,
          state: db.DBInstanceStatus ?? null,
          createdAt: db.InstanceCreateTime ? new Date(db.InstanceCreateTime).toISOString() : null,
          encryptionAtRest: db.StorageEncrypted ?? null,
          kmsKeyId: db.KmsKeyId ?? null,
          vlanNetworkId: db.DBSubnetGroup?.VpcId ?? null,
        });
      }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`RDS instances (rds:DescribeDBInstances): ${e.message}`); }

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
        uniqueId: `arn:aws:s3:::${b.Name}`,
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
          virtual: true,
          location: region,
          assetType: 'Serverless Function',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: fn.Runtime ?? null,
          vlanNetworkId: fn.VpcConfig?.VpcId ?? null,
          function: fn.FunctionName,
        });
      }
      marker = r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`Lambda functions (lambda:ListFunctions): ${e.message}`); }

  // ELBv2 load balancers (ALB/NLB/GLB)
  try {
    const elbv2 = aws.elbv2(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await elbv2.send(new DescribeLoadBalancersCommand({ Marker: marker, PageSize: 100 }));
      for (const lb of r.LoadBalancers ?? []) {
        if (!lb.LoadBalancerArn) continue;
        assets.push({
          provider: 'aws',
          uniqueId: lb.LoadBalancerArn,
          virtual: true,
          publicFacing: lb.Scheme === 'internet-facing',
          dns: lb.DNSName ?? null,
          location: region,
          assetType: 'Load Balancer',
          hardwareMakeModel: `AWS ELB ${lb.Type ?? ''}`.trim(),
          vlanNetworkId: lb.VpcId ?? null,
          function: lb.LoadBalancerName ?? null,
        });
      }
      marker = r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`ELBv2 (elasticloadbalancing:DescribeLoadBalancers): ${e.message}`); }

  // DynamoDB tables
  try {
    const ddb = aws.dynamodb(auth);
    let start: string | undefined; let pages = 0;
    do {
      const r = await ddb.send(new ListTablesCommand({ ExclusiveStartTableName: start, Limit: 100 }));
      for (const name of r.TableNames ?? []) {
        let dArn: string | undefined;
        try { const d = await ddb.send(new DescribeTableCommand({ TableName: name })); dArn = d.Table?.TableArn; } catch { /* keep null */ }
        assets.push({
          provider: 'aws',
          uniqueId: dArn ?? arn('dynamodb', `table/${name}`),
          virtual: true,
          location: region,
          assetType: 'Database',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: 'Amazon DynamoDB',
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
          virtual: true,
          dns: repo.repositoryUri ?? null,
          location: region,
          assetType: 'Container Registry',
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
        let version: string | null = null; let cArn: string | undefined; let cVpc: string | null = null; let endpoint: string | null = null;
        try {
          const d = await eks.send(new DescribeClusterCommand({ name }));
          version = d.cluster?.version ?? null; cArn = d.cluster?.arn;
          cVpc = d.cluster?.resourcesVpcConfig?.vpcId ?? null; endpoint = d.cluster?.endpoint ?? null;
        } catch { /* keep nulls */ }
        assets.push({
          provider: 'aws',
          uniqueId: cArn ?? arn('eks', `cluster/${name}`),
          virtual: true,
          dns: endpoint,
          location: region,
          assetType: 'Kubernetes Cluster',
          softwareDatabaseVendor: 'AWS',
          softwareDatabaseNameVersion: version ? `Amazon EKS ${version}` : 'Amazon EKS',
          vlanNetworkId: cVpc,
          function: name,
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
          virtual: true,
          publicFacing: true, // CloudFront distributions are internet-facing CDN edges
          dns: d.DomainName ?? null,
          location: 'global',
          assetType: 'CDN Distribution',
          function: d.Comment || d.Id || null,
        });
      }
      marker = r.DistributionList?.NextMarker && r.DistributionList.NextMarker !== marker ? r.DistributionList.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`CloudFront (cloudfront:ListDistributions): ${e.message}`); }

  // SSM Inventory (INV-12): enrich EC2 instances with real OS name/version from
  // managed-instance information (the API-reported OS, richer than PlatformDetails).
  try {
    const ssm = aws.ssm(auth);
    const osById = new Map<string, string>();
    let token: string | undefined; let pages = 0;
    do {
      const r = await ssm.send(new GetInventoryCommand({ NextToken: token, MaxResults: 50 }));
      for (const ent of r.Entities ?? []) {
        const content = ent.Data?.['AWS:InstanceInformation']?.Content?.[0];
        if (ent.Id && content) {
          const os = [content.PlatformName, content.PlatformVersion].filter(Boolean).join(' ');
          if (os) osById.set(ent.Id, os);
        }
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
    if (osById.size) {
      for (const a of assets) {
        if (a.resourceType !== 'AWS::EC2::Instance') continue;
        const id = a.uniqueId.split('/').pop();
        const os = id ? osById.get(id) : undefined;
        if (os) a.osNameVersion = os; // SSM-reported OS is authoritative over PlatformDetails
      }
    }
  } catch (e: any) { warnings.push(`SSM Inventory (ssm:GetInventory): ${e.message}`); }

  // Stamp common provenance on every asset (account / collected-at / source).
  const now = new Date().toISOString();
  for (const a of assets) {
    a.accountId ??= account;
    a.collectedAt ??= now;
    a.sourceApi ??= 'aws-sdk';
  }

  return { assets, warnings };
}
