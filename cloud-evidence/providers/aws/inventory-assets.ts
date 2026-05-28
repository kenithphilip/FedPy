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
import * as aws from '../../core/auth/aws.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

export interface AwsAssetResult { assets: CloudAsset[]; warnings: string[]; }

function tag(tags: Array<{ Key?: string; Value?: string }> | undefined, key: string): string | undefined {
  return tags?.find((t) => (t.Key ?? '').toLowerCase() === key.toLowerCase())?.Value || undefined;
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
            systemOwner: tag(inst.Tags, 'Owner') ?? null,
            function: tag(inst.Tags, 'Name') ?? tag(inst.Tags, 'Function') ?? null,
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
          function: tag(v.Tags, 'Name') ?? null,
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

  return { assets, warnings };
}
