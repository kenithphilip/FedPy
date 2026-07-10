/**
 * Additional AWS depth-enrichers — the "complete the picture" collectors.
 *
 * Adds the common services the backbone only saw shallowly, with their
 * encryption / endpoint signals so the FIPS + inventory lenses are complete:
 *   - ElastiCache (Redis/Memcached): at-rest + in-transit encryption
 *   - Redshift: encrypted + KMS + publicly-accessible
 *   - EFS: encrypted at rest + KMS
 *   - SNS topics / SQS queues: SSE (KMS) at rest
 *   - API Gateway REST APIs: endpoint type (private vs edge/regional)
 *   - Route 53 hosted zones: public vs private DNS
 *
 * Read-only, guardrail-wrapped clients. Pure mappers exported for tests.
 */
import { DescribeReplicationGroupsCommand, DescribeCacheClustersCommand } from '@aws-sdk/client-elasticache';
import { DescribeClustersCommand as RedshiftDescribeClustersCommand } from '@aws-sdk/client-redshift';
import { DescribeFileSystemsCommand } from '@aws-sdk/client-efs';
import { ListTopicsCommand, GetTopicAttributesCommand } from '@aws-sdk/client-sns';
import { ListQueuesCommand, GetQueueAttributesCommand } from '@aws-sdk/client-sqs';
import { GetRestApisCommand } from '@aws-sdk/client-api-gateway';
import { ListHostedZonesCommand } from '@aws-sdk/client-route-53';
import { ListCertificatesCommand, DescribeCertificateCommand } from '@aws-sdk/client-acm';
import { DescribeDBClustersCommand } from '@aws-sdk/client-rds';
import { DescribeAutoScalingGroupsCommand } from '@aws-sdk/client-auto-scaling';
import * as aws from '../../core/auth/aws.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

const MAX_PAGES = 200;

export interface AwsServicesResult { assets: CloudAsset[]; warnings: string[]; }

// --------------------------------------------------------------------------- #
// Pure mappers (unit-tested without cloud calls)
// --------------------------------------------------------------------------- #

/** ElastiCache replication group → asset (at-rest + in-transit encryption). */
export function elastiCacheRgToAsset(rg: any, region: string): CloudAsset | null {
  if (!rg?.ARN && !rg?.ReplicationGroupId) return null;
  return {
    provider: 'aws',
    uniqueId: rg.ARN ?? `arn:${aws.awsPartition(region)}::elasticache:${region}:replicationgroup/${rg.ReplicationGroupId}`,
    resourceType: 'AWS::ElastiCache::ReplicationGroup',
    virtual: true,
    location: region,
    assetType: 'Cache',
    function: rg.ReplicationGroupId ?? null,
    softwareDatabaseVendor: 'AWS',
    softwareDatabaseNameVersion: 'ElastiCache Redis',
    state: rg.Status ?? null,
    encryptionAtRest: rg.AtRestEncryptionEnabled ?? null,
    encryptionInTransit: rg.TransitEncryptionEnabled ?? null,
    kmsKeyId: rg.KmsKeyId ?? null,
  };
}

/** Redshift cluster → asset. */
export function redshiftToAsset(c: any, region: string): CloudAsset | null {
  if (!c?.ClusterIdentifier) return null;
  return {
    provider: 'aws',
    uniqueId: `arn:${aws.awsPartition(region)}:redshift:${region}::cluster:${c.ClusterIdentifier}`,
    resourceType: 'AWS::Redshift::Cluster',
    virtual: true,
    location: c.AvailabilityZone ?? region,
    assetType: 'Data Warehouse',
    function: c.ClusterIdentifier,
    softwareDatabaseVendor: 'AWS',
    softwareDatabaseNameVersion: `Amazon Redshift ${c.ClusterVersion ?? ''}`.trim(),
    state: c.ClusterStatus ?? null,
    publicFacing: c.PubliclyAccessible ?? undefined,
    encryptionAtRest: c.Encrypted ?? null,
    kmsKeyId: c.KmsKeyId ?? null,
    vlanNetworkId: c.VpcId ?? null,
    dns: c.Endpoint?.Address ?? null,
  };
}

/** EFS file system → asset. */
export function efsToAsset(fs: any, region: string): CloudAsset | null {
  if (!fs?.FileSystemId) return null;
  return {
    provider: 'aws',
    uniqueId: fs.FileSystemArn ?? `arn:${aws.awsPartition(region)}:elasticfilesystem:${region}::file-system/${fs.FileSystemId}`,
    resourceType: 'AWS::EFS::FileSystem',
    virtual: true,
    location: region,
    assetType: 'File System',
    function: fs.Name ?? fs.FileSystemId,
    state: fs.LifeCycleState ?? null,
    encryptionAtRest: fs.Encrypted ?? null,
    kmsKeyId: fs.KmsKeyId ?? null,
    sizeGb: fs.SizeInBytes?.Value != null ? Math.round((fs.SizeInBytes.Value / 1_073_741_824) * 100) / 100 : null,
  };
}

/** SNS topic attributes → asset (SSE via KmsMasterKeyId). */
export function snsTopicToAsset(arn: string, attrs: Record<string, string> | undefined, region: string): CloudAsset | null {
  if (!arn) return null;
  const kms = attrs?.KmsMasterKeyId;
  return {
    provider: 'aws',
    uniqueId: arn,
    resourceType: 'AWS::SNS::Topic',
    virtual: true,
    location: region,
    assetType: 'Messaging Topic',
    function: arn.split(':').pop() ?? arn,
    encryptionAtRest: kms ? true : (attrs ? false : null),
    kmsKeyId: kms ?? null,
  };
}

/** SQS queue attributes → asset (SSE via KmsMasterKeyId or SqsManagedSseEnabled). */
export function sqsQueueToAsset(url: string, attrs: Record<string, string> | undefined, region: string, account: string | null): CloudAsset | null {
  if (!url) return null;
  const name = url.split('/').pop() ?? url;
  const kms = attrs?.KmsMasterKeyId;
  const sseManaged = attrs?.SqsManagedSseEnabled === 'true';
  return {
    provider: 'aws',
    uniqueId: attrs?.QueueArn ?? `arn:${aws.awsPartition(region)}:sqs:${region}:${account ?? ''}:${name}`,
    resourceType: 'AWS::SQS::Queue',
    virtual: true,
    location: region,
    assetType: 'Messaging Queue',
    function: name,
    encryptionAtRest: kms || sseManaged ? true : (attrs ? false : null),
    kmsKeyId: kms ?? null,
    comments: sseManaged ? 'SQS-managed SSE' : undefined,
  };
}

/** API Gateway REST API → asset (endpoint type = private vs public). */
export function apiGatewayToAsset(api: any, region: string): CloudAsset | null {
  if (!api?.id) return null;
  const types: string[] = api.endpointConfiguration?.types ?? [];
  const isPrivate = types.includes('PRIVATE');
  return {
    provider: 'aws',
    uniqueId: `arn:${aws.awsPartition(region)}:apigateway:${region}::/restapis/${api.id}`,
    resourceType: 'AWS::ApiGateway::RestApi',
    virtual: true,
    location: region,
    assetType: 'API Gateway',
    function: api.name ?? api.id,
    publicFacing: types.length ? !isPrivate : undefined,
    createdAt: api.createdDate ? new Date(api.createdDate).toISOString() : null,
    comments: types.length ? `endpoint: ${types.join(', ')}` : undefined,
  };
}

/** Route 53 hosted zone → asset (public vs private DNS). */
export function route53ZoneToAsset(z: any, region: string): CloudAsset | null {
  if (!z?.Id) return null;
  const priv = z.Config?.PrivateZone === true;
  return {
    provider: 'aws',
    uniqueId: `arn:${aws.awsPartition(region)}:route53:::hostedzone/${String(z.Id).replace('/hostedzone/', '')}`,
    resourceType: 'AWS::Route53::HostedZone',
    virtual: true,
    location: 'global',
    assetType: 'DNS Hosted Zone',
    function: z.Name ?? z.Id,
    publicFacing: !priv,
    dns: z.Name ?? null,
    comments: priv ? 'private hosted zone' : 'public hosted zone',
  };
}

/** ACM certificate detail → asset (expiry, algorithm, renewal, in-use). SC-8. */
export function acmCertToAsset(c: any, region: string, nowMs: number): CloudAsset | null {
  if (!c?.CertificateArn) return null;
  const notAfter = c.NotAfter ? new Date(c.NotAfter) : null;
  const daysToExpiry = notAfter ? Math.floor((notAfter.getTime() - nowMs) / 86_400_000) : null;
  const inUse = (c.InUseBy ?? []).length > 0;
  const notes: string[] = [];
  if (daysToExpiry != null && daysToExpiry < 0) notes.push('EXPIRED');
  else if (daysToExpiry != null && daysToExpiry < 30) notes.push(`expires in ${daysToExpiry}d`);
  if (c.RenewalSummary?.RenewalStatus) notes.push(`renewal: ${c.RenewalSummary.RenewalStatus}`);
  if (!inUse) notes.push('not in use');
  return {
    provider: 'aws',
    uniqueId: c.CertificateArn,
    resourceType: 'AWS::ACM::Certificate',
    virtual: true,
    location: region,
    assetType: 'Certificate',
    function: c.DomainName ?? c.CertificateArn,
    state: c.Status ?? null,
    // Cert key algorithm (e.g. RSA-2048, EC_prime256v1) → software/version slot.
    softwareDatabaseNameVersion: c.KeyAlgorithm ?? null,
    // Reuse endOfLife for cert expiry (the workbook highlights any non-empty EOL).
    endOfLife: notAfter ? notAfter.toISOString().slice(0, 10) : null,
    dns: c.DomainName ?? null,
    comments: notes.length ? notes.join('; ') : undefined,
  };
}

/** RDS Aurora (or Multi-AZ) cluster → asset. */
export function rdsClusterToAsset(c: any, region: string): CloudAsset | null {
  if (!c?.DBClusterIdentifier && !c?.DBClusterArn) return null;
  return {
    provider: 'aws',
    uniqueId: c.DBClusterArn ?? `arn:${aws.awsPartition(region)}:rds:${region}::cluster:${c.DBClusterIdentifier}`,
    resourceType: 'AWS::RDS::DBCluster',
    virtual: true,
    location: region,
    assetType: 'Database Cluster',
    function: c.DBClusterIdentifier ?? null,
    softwareDatabaseVendor: c.Engine ?? null,
    softwareDatabaseNameVersion: [c.Engine, c.EngineVersion].filter(Boolean).join(' ') || null,
    hardwareMakeModel: c.MultiAZ ? 'Aurora (Multi-AZ)' : 'Aurora',
    state: c.Status ?? null,
    publicFacing: c.PubliclyAccessible ?? undefined,
    dns: c.Endpoint ?? null,
    encryptionAtRest: c.StorageEncrypted ?? null,
    // Aurora enforces TLS in transit natively; treat as true when known-encrypted engine.
    encryptionInTransit: c.StorageEncrypted != null ? true : null,
    kmsKeyId: c.KmsKeyId ?? null,
    vlanNetworkId: c.VpcId ?? null,
    createdAt: c.ClusterCreateTime ? new Date(c.ClusterCreateTime).toISOString() : null,
  };
}

/** Auto Scaling group → asset (capacity + launch template context). */
export function asgToAsset(g: any, region: string): CloudAsset | null {
  if (!g?.AutoScalingGroupName) return null;
  const lt = g.LaunchTemplate?.LaunchTemplateName
    ?? g.MixedInstancesPolicy?.LaunchTemplate?.LaunchTemplateSpecification?.LaunchTemplateName
    ?? g.LaunchConfigurationName ?? null;
  return {
    provider: 'aws',
    uniqueId: g.AutoScalingGroupARN ?? `arn:${aws.awsPartition(region)}:autoscaling:${region}::autoScalingGroup:${g.AutoScalingGroupName}`,
    resourceType: 'AWS::AutoScaling::AutoScalingGroup',
    virtual: true,
    location: region,
    assetType: 'Auto Scaling Group',
    function: g.AutoScalingGroupName,
    state: `desired=${g.DesiredCapacity ?? '?'} min=${g.MinSize ?? '?'} max=${g.MaxSize ?? '?'}`,
    createdAt: g.CreatedTime ? new Date(g.CreatedTime).toISOString() : null,
    comments: [lt ? `launch template: ${lt}` : null, `instances: ${(g.Instances ?? []).length}`].filter(Boolean).join('; ') || undefined,
  };
}

// --------------------------------------------------------------------------- #
// Collector
// --------------------------------------------------------------------------- #

export async function collectAwsServiceAssets(
  auth: aws.AwsAuth,
  account: string | null,
  opts: { includeGlobal?: boolean; nowMs?: number } = {},
): Promise<AwsServicesResult> {
  const includeGlobal = opts.includeGlobal ?? true;
  const nowMs = opts.nowMs ?? Date.now();
  const assets: CloudAsset[] = [];
  const warnings: string[] = [];
  const region = auth.region;

  // ElastiCache — prefer replication groups (Redis); fall back to cache clusters.
  try {
    const ec = aws.elasticache(auth);
    let marker: string | undefined; let pages = 0; let sawRg = false;
    do {
      const r = await ec.send(new DescribeReplicationGroupsCommand({ Marker: marker }));
      for (const rg of r.ReplicationGroups ?? []) { const a = elastiCacheRgToAsset(rg, region); if (a) { assets.push(a); sawRg = true; } }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
    // Memcached / standalone nodes not in a replication group.
    let cmarker: string | undefined; pages = 0;
    do {
      const r = await ec.send(new DescribeCacheClustersCommand({ Marker: cmarker }));
      for (const cc of r.CacheClusters ?? []) {
        if (sawRg && cc.ReplicationGroupId) continue; // covered by the RG above
        if (!cc.CacheClusterId) continue;
        assets.push({
          provider: 'aws', uniqueId: cc.ARN ?? `arn:${aws.awsPartition(region)}:elasticache:${region}:${account ?? ''}:cluster:${cc.CacheClusterId}`,
          resourceType: 'AWS::ElastiCache::CacheCluster', virtual: true, location: region, assetType: 'Cache',
          function: cc.CacheClusterId, softwareDatabaseVendor: 'AWS', softwareDatabaseNameVersion: `ElastiCache ${cc.Engine ?? ''} ${cc.EngineVersion ?? ''}`.trim(),
          state: cc.CacheClusterStatus ?? null, encryptionAtRest: cc.AtRestEncryptionEnabled ?? null, encryptionInTransit: cc.TransitEncryptionEnabled ?? null,
        });
      }
      cmarker = r.Marker && r.Marker !== cmarker ? r.Marker : undefined;
    } while (cmarker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'elasticache.DescribeReplicationGroups', 'elasticache:DescribeReplicationGroups')); }

  // Redshift.
  try {
    const rs = aws.redshift(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await rs.send(new RedshiftDescribeClustersCommand({ Marker: marker }));
      for (const c of r.Clusters ?? []) { const a = redshiftToAsset(c, region); if (a) assets.push(a); }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'redshift.DescribeClusters', 'redshift:DescribeClusters')); }

  // EFS.
  try {
    const efs = aws.efs(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await efs.send(new DescribeFileSystemsCommand({ Marker: token }));
      for (const fs of r.FileSystems ?? []) { const a = efsToAsset(fs, region); if (a) assets.push(a); }
      token = r.NextMarker && r.NextMarker !== token ? r.NextMarker : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'efs.DescribeFileSystems', 'elasticfilesystem:DescribeFileSystems')); }

  // SNS topics (+ per-topic attributes for SSE).
  try {
    const sns = aws.sns(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await sns.send(new ListTopicsCommand({ NextToken: token }));
      for (const t of r.Topics ?? []) {
        if (!t.TopicArn) continue;
        let attrs: Record<string, string> | undefined;
        try { const at = await sns.send(new GetTopicAttributesCommand({ TopicArn: t.TopicArn })); attrs = at.Attributes; } catch { /* keep null → unknown */ }
        const a = snsTopicToAsset(t.TopicArn, attrs, region); if (a) assets.push(a);
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'sns.ListTopics', 'sns:ListTopics')); }

  // SQS queues (+ per-queue attributes for SSE).
  try {
    const sqs = aws.sqs(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await sqs.send(new ListQueuesCommand({ NextToken: token, MaxResults: 1000 }));
      for (const url of r.QueueUrls ?? []) {
        let attrs: Record<string, string> | undefined;
        try { const at = await sqs.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['QueueArn', 'KmsMasterKeyId', 'SqsManagedSseEnabled'] })); attrs = at.Attributes; } catch { /* unknown */ }
        const a = sqsQueueToAsset(url, attrs, region, account); if (a) assets.push(a);
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'sqs.ListQueues', 'sqs:ListQueues')); }

  // API Gateway REST APIs.
  try {
    const ag = aws.apigateway(auth);
    let pos: string | undefined; let pages = 0;
    do {
      const r = await ag.send(new GetRestApisCommand({ position: pos, limit: 500 }));
      for (const api of r.items ?? []) { const a = apiGatewayToAsset(api, region); if (a) assets.push(a); }
      pos = r.position && r.position !== pos ? r.position : undefined;
    } while (pos && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'apigateway.GetRestApis', 'apigateway:GET')); }

  // Route 53 hosted zones (global — once).
  if (includeGlobal) try {
    const r53 = aws.route53(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await r53.send(new ListHostedZonesCommand({ Marker: marker }));
      for (const z of r.HostedZones ?? []) { const a = route53ZoneToAsset(z, region); if (a) assets.push(a); }
      marker = r.IsTruncated && r.NextMarker && r.NextMarker !== marker ? r.NextMarker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'route53.ListHostedZones', 'route53:ListHostedZones')); }

  // ACM certificates (+ per-cert detail for expiry / algorithm / renewal / in-use).
  try {
    const acm = aws.acm(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await acm.send(new ListCertificatesCommand({ NextToken: token, MaxItems: 100 }));
      for (const summary of r.CertificateSummaryList ?? []) {
        if (!summary.CertificateArn) continue;
        try {
          const d = await acm.send(new DescribeCertificateCommand({ CertificateArn: summary.CertificateArn }));
          const a = acmCertToAsset(d.Certificate, region, nowMs); if (a) assets.push(a);
        } catch (e: any) { warnings.push(diagnoseAwsError(e, `acm.DescribeCertificate ${summary.CertificateArn}`, 'acm:DescribeCertificate')); }
      }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'acm.ListCertificates', 'acm:ListCertificates')); }

  // RDS Aurora / Multi-AZ clusters (distinct from DBInstance).
  try {
    const rds = aws.rds(auth);
    let marker: string | undefined; let pages = 0;
    do {
      const r = await rds.send(new DescribeDBClustersCommand({ Marker: marker, MaxRecords: 100 }));
      for (const c of r.DBClusters ?? []) { const a = rdsClusterToAsset(c, region); if (a) assets.push(a); }
      marker = r.Marker && r.Marker !== marker ? r.Marker : undefined;
    } while (marker && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'rds.DescribeDBClusters', 'rds:DescribeDBClusters')); }

  // Auto Scaling groups (capacity + launch template context).
  try {
    const as = aws.autoScaling(auth);
    let token: string | undefined; let pages = 0;
    do {
      const r = await as.send(new DescribeAutoScalingGroupsCommand({ NextToken: token, MaxRecords: 100 }));
      for (const g of r.AutoScalingGroups ?? []) { const a = asgToAsset(g, region); if (a) assets.push(a); }
      token = r.NextToken && r.NextToken !== token ? r.NextToken : undefined;
    } while (token && ++pages < MAX_PAGES);
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'autoscaling.DescribeAutoScalingGroups', 'autoscaling:DescribeAutoScalingGroups')); }

  const now = new Date().toISOString();
  for (const a of assets) { a.accountId ??= account; a.collectedAt ??= now; a.sourceApi ??= 'aws-sdk-services'; }
  return { assets, warnings };
}
