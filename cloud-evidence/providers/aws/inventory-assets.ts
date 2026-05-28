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
import { DescribeInstancesCommand, DescribeVolumesCommand } from '@aws-sdk/client-ec2';
import { DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { ListBucketsCommand, GetBucketLocationCommand } from '@aws-sdk/client-s3';
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

/** Enumerate AWS assets in one region and normalize to workbook rows. */
export async function collectAwsAssets(auth: aws.AwsAuth, account: string | null): Promise<AwsAssetResult> {
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  const region = auth.region;
  const arn = (svc: string, resource: string) => `arn:aws:${svc}:${region}:${account ?? ''}:${resource}`;

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
          for (const ni of inst.NetworkInterfaces ?? []) {
            for (const pip of ni.PrivateIpAddresses ?? []) {
              if (pip.PrivateIpAddress) { ips.push(pip.PrivateIpAddress); macs.push(ni.MacAddress ?? ''); }
              if (pip.Association?.PublicIp) { ips.push(pip.Association.PublicIp); macs.push(ni.MacAddress ?? ''); }
            }
          }
          assets.push({
            provider: 'aws',
            uniqueId: arn('ec2', `instance/${inst.InstanceId}`),
            ips,
            macs,
            virtual: true,
            publicFacing: Boolean(inst.PublicIpAddress),
            dns: inst.PublicDnsName || inst.PrivateDnsName || null,
            osNameVersion: inst.PlatformDetails ?? (inst.Platform ?? null),
            location: inst.Placement?.AvailabilityZone ?? region,
            assetType: 'Compute Instance',
            hardwareMakeModel: `AWS EC2 ${inst.InstanceType ?? ''}`.trim(),
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
          virtual: true,
          location: v.AvailabilityZone ?? region,
          assetType: 'Storage Volume',
          hardwareMakeModel: `AWS EBS ${v.VolumeType ?? ''}`.trim(),
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
          ips: db.Endpoint?.Address ? [db.Endpoint.Address] : undefined,
          virtual: true,
          publicFacing: Boolean(db.PubliclyAccessible),
          dns: db.Endpoint?.Address ?? null,
          location: db.AvailabilityZone ?? region,
          assetType: 'Database',
          softwareDatabaseVendor: db.Engine ?? null,
          softwareDatabaseNameVersion: [db.Engine, db.EngineVersion].filter(Boolean).join(' ') || null,
          vlanNetworkId: db.DBSubnetGroup?.VpcId ?? null,
        });
      }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(`RDS instances (rds:DescribeDBInstances): ${e.message}`); }

  // S3 buckets (global; emit once per region run is fine — they're account-global)
  try {
    const s3 = aws.s3(auth);
    const r = await s3.send(new ListBucketsCommand({}));
    for (const b of r.Buckets ?? []) {
      if (!b.Name) continue;
      let loc: string | null = null;
      try {
        const l = await s3.send(new GetBucketLocationCommand({ Bucket: b.Name }));
        loc = (l.LocationConstraint as string) || 'us-east-1';
      } catch { /* keep null on per-bucket error */ }
      assets.push({
        provider: 'aws',
        uniqueId: `arn:aws:s3:::${b.Name}`,
        virtual: true,
        location: loc,
        assetType: 'Object Storage Bucket',
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

  // CloudFront distributions (global)
  try {
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

  return { assets, warnings };
}
