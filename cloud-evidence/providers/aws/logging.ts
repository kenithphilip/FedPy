/**
 * AWS logging-domain collectors.
 * Covers 5 MLA KSIs + CMT-LMC.
 */
import {
  DescribeTrailsCommand, GetTrailStatusCommand, GetEventSelectorsCommand, GetInsightSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  DescribeLogGroupsCommand, DescribeSubscriptionFiltersCommand,
} from '@aws-sdk/client-cloudwatch-logs';
import { GetBucketEncryptionCommand, GetBucketVersioningCommand, GetBucketPolicyCommand, GetObjectLockConfigurationCommand, ListBucketsCommand } from '@aws-sdk/client-s3';
import { GetEnabledStandardsCommand, GetFindingsCommand as ShGetFindingsCommand } from '@aws-sdk/client-securityhub';
import { DescribeConfigurationRecordersCommand, DescribeConfigurationRecorderStatusCommand } from '@aws-sdk/client-config-service';
import { ListDeliveryStreamsCommand, DescribeDeliveryStreamCommand } from '@aws-sdk/client-firehose';
import { ListDataLakesCommand, ListSubscribersCommand } from '@aws-sdk/client-securitylake';
import { ListWorkGroupsCommand, ListNamedQueriesCommand } from '@aws-sdk/client-athena';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';
import { diagnoseAwsError } from '../../core/error-diagnostics.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

// ---- Shared trail inventory (used by both CMT-LMC and MLA-LET) ----
interface TrailRecord {
  arn: string;
  name: string;
  isMultiRegion: boolean;
  isOrganizationTrail: boolean;
  logFileValidationEnabled: boolean;
  s3Bucket: string;
  kmsKeyId?: string;
  isLogging: boolean;
  eventSelectors: any[];
  insightSelectors: any[];
  /** GetEventSelectors succeeded for this trail (an empty eventSelectors is real, not a read failure). */
  eventSelectorsRead: boolean;
  /** GetInsightSelectors succeeded for this trail. */
  insightSelectorsRead: boolean;
}

/**
 * Gate a "no violations found" pass on the underlying fetch(es) having actually
 * succeeded. If any prerequisite source failed to collect (AccessDenied /
 * throttle / etc.), an empty violation list is INDETERMINATE, not clean — so we
 * force `passed=false` rather than emit a false PASS. See gatePass usage below.
 */
function gatePass(noViolations: boolean, collected: Set<string>, ...required: string[]): boolean {
  return required.every((r) => collected.has(r)) && noViolations;
}

async function fetchTrails(ctx: Ctx): Promise<{ trails: TrailRecord[]; warnings: string[]; evidence: RawEvidence[]; collected: Set<string> }> {
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const trails: TrailRecord[] = [];
  // Records which fetches SUCCEEDED. A "no violations" finding derived from
  // trails must be gated on the DescribeTrails call (and, where relevant, the
  // per-trail event/insight-selector reads) having actually run — otherwise an
  // AccessDenied that leaves the list empty produces a false PASS.
  const collected = new Set<string>();
  try {
    const ct = aws.cloudtrail(ctx.auth);
    const r = await ct.send(new DescribeTrailsCommand({}));
    let allEventSelectorsRead = true;
    let allInsightSelectorsRead = true;
    for (const t of r.trailList ?? []) {
      if (!t.TrailARN || !t.Name) continue;
      let isLogging = false;
      let es: any[] = [];
      let is: any[] = [];
      let eventSelectorsRead = false;
      let insightSelectorsRead = false;
      try {
        const status = await ct.send(new GetTrailStatusCommand({ Name: t.TrailARN }));
        isLogging = !!status.IsLogging;
      } catch (e: any) { warnings.push(diagnoseAwsError(e, `cloudtrail.GetTrailStatus ${t.Name}`, 'cloudtrail:GetTrailStatus')); }
      try {
        const sels = await ct.send(new GetEventSelectorsCommand({ TrailName: t.TrailARN }));
        es = sels.EventSelectors ?? sels.AdvancedEventSelectors ?? [];
        eventSelectorsRead = true;
      } catch (e: any) { allEventSelectorsRead = false; warnings.push(diagnoseAwsError(e, `cloudtrail.GetEventSelectors ${t.Name}`, 'cloudtrail:GetEventSelectors')); }
      try {
        const ins = await ct.send(new GetInsightSelectorsCommand({ TrailName: t.TrailARN }));
        is = ins.InsightSelectors ?? [];
        insightSelectorsRead = true;
      } catch (e: any) {
        // InsightSelectors are not configured on many trails; the API returns an
        // error in that case. Distinguish a read failure (denied/throttle) from
        // "not configured" so a permission gap does not masquerade as "no insights".
        allInsightSelectorsRead = false;
        warnings.push(diagnoseAwsError(e, `cloudtrail.GetInsightSelectors ${t.Name}`, 'cloudtrail:GetInsightSelectors'));
      }
      trails.push({
        arn: t.TrailARN,
        name: t.Name,
        isMultiRegion: !!t.IsMultiRegionTrail,
        isOrganizationTrail: !!t.IsOrganizationTrail,
        logFileValidationEnabled: !!t.LogFileValidationEnabled,
        s3Bucket: t.S3BucketName ?? '',
        kmsKeyId: t.KmsKeyId,
        isLogging,
        eventSelectors: es,
        insightSelectors: is,
        eventSelectorsRead,
        insightSelectorsRead,
      });
    }
    collected.add('trails');
    if (allEventSelectorsRead) collected.add('eventSelectors');
    if (allInsightSelectorsRead) collected.add('insightSelectors');
    evidence.push(ev('cloudtrail.trail_inventory', trails));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'cloudtrail.DescribeTrails', 'cloudtrail:DescribeTrails')); }
  return { trails, warnings, evidence, collected };
}

// =====================================================================
// KSI-CMT-LMC — Logging Changes
// =====================================================================
export async function collectCmtLmc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { trails, warnings, evidence, collected } = await fetchTrails(ctx);

  // Inspect destination buckets for the trails
  interface BucketAudit { bucket: string; versioning: string | null; objectLock: boolean; sseAlgo: string | null; }
  const bucketAudits: BucketAudit[] = [];
  const s3 = aws.s3(ctx.auth);
  const seenBuckets = new Set<string>();
  for (const t of trails) {
    if (!t.s3Bucket || seenBuckets.has(t.s3Bucket)) continue;
    seenBuckets.add(t.s3Bucket);
    const a: BucketAudit = { bucket: t.s3Bucket, versioning: null, objectLock: false, sseAlgo: null };
    try {
      const v = await s3.send(new GetBucketVersioningCommand({ Bucket: t.s3Bucket }));
      a.versioning = v.Status ?? null;
    } catch { /* ignore */ }
    try {
      const o = await s3.send(new GetObjectLockConfigurationCommand({ Bucket: t.s3Bucket }));
      a.objectLock = !!o.ObjectLockConfiguration?.ObjectLockEnabled;
    } catch { /* not all buckets have it */ }
    try {
      const e = await s3.send(new GetBucketEncryptionCommand({ Bucket: t.s3Bucket }));
      a.sseAlgo = e.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm ?? null;
    } catch { /* ignore */ }
    bucketAudits.push(a);
  }
  evidence.push(ev('s3.cloudtrail_destination_bucket_audit', bucketAudits));

  // AWS Config recorder (also relevant for change visibility)
  let configRecorderHealthy = false;
  try {
    const cfg = aws.configService(ctx.auth);
    const recs = await cfg.send(new DescribeConfigurationRecordersCommand({}));
    if ((recs.ConfigurationRecorders ?? []).length > 0) {
      const stat = await cfg.send(new DescribeConfigurationRecorderStatusCommand({}));
      configRecorderHealthy = (stat.ConfigurationRecordersStatus ?? []).some((s: any) => s.recording === true && s.lastStatus === 'SUCCESS');
    }
    evidence.push(ev('config.recorder_status_for_lmc', { healthy: configRecorderHealthy }));
  } catch (e: any) { warnings.push(`Config: ${e.message}`); }

  const orgTrails = trails.filter((t) => t.isOrganizationTrail && t.isMultiRegion && t.isLogging);
  const trailsWithValidation = trails.filter((t) => t.logFileValidationEnabled);
  const trailsWithKms = trails.filter((t) => !!t.kmsKeyId);
  const trailsWithInsights = trails.filter((t) => t.insightSelectors.length > 0);
  const bucketsWithoutLock = bucketAudits.filter((b) => !b.objectLock).map((b) => b.bucket);
  const bucketsWithoutKms = bucketAudits.filter((b) => b.sseAlgo !== 'aws:kms').map((b) => b.bucket);
  const bucketsWithoutVersioning = bucketAudits.filter((b) => b.versioning !== 'Enabled').map((b) => b.bucket);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party audit-log forwarder + cold storage (Datadog Cloud SIEM, Splunk, Sumo Logic)',
      description: 'Change logs may be exported off-cloud to a 3rd-party SIEM that provides tamper-resistant retention. The cloud side then primarily provides the source.',
      evidence_required: ['SIEM ingestion config showing CloudTrail source', 'Sample query showing change events present', 'Retention/immutability proof from the SIEM vendor'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.cloudtrail.org_multi_region_trail_logging',
      passed: orgTrails.length >= 1,
      severity: 'critical',
      current: {
        summary: orgTrails.length >= 1
          ? `${orgTrails.length} multi-region, org-wide trail(s) actively logging.`
          : `${trails.length} trail(s) found; 0 are multi-region + org-wide + actively logging.`,
        observations: { all_trails: trails, org_multi_region_active: orgTrails.length },
      },
      target: { summary: 'At least one multi-region, organization-wide CloudTrail trail is actively logging.', rationale: 'NIST AU-2, CM-3. Without org-wide multi-region capture, change events in some account/region are invisible.' },
      gap: orgTrails.length >= 1 ? undefined : {
        description: 'Change visibility has gaps; an attacker can operate in an unlogged region.',
        affected_resources: [{ type: 'aws_cloudtrail', identifier: 'org-trail', attributes: { existing_trail_count: trails.length } }],
      },
      remediation: orgTrails.length >= 1 ? undefined : {
        summary: 'Create a multi-region, org-wide trail from the management account.',
        options: [{
          approach: 'Create org trail via Terraform from management account.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'CloudTrail mgmt events to S3 are free for one trail per account; additional trails + data events incur cost.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Trail + S3 bucket + KMS + Object Lock setup.' },
          steps: [
            'Create an Object-Locked S3 bucket in the security-tooling account.',
            'Create a CMK in the same account with appropriate key policy.',
            'From the management account, create a multi-region org trail pointing at the bucket + CMK.',
            'Verify activity from a member account flows in.',
          ],
          example_code: `resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.bucket
  is_organization_trail         = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  insight_selector { insight_type = "ApiCallRateInsight" }
}`,
          references: [{ title: 'CloudTrail for org', url: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['au-2','au-3','au-12','cm-3.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'Same CloudTrail provides MLA-LET event-type coverage.' },
        { ksi_id: 'KSI-MLA-ALA', relationship: 'shares-remediation', note: 'The destination bucket\'s IAM is the ALA evidence.' },
      ],
    }),

    finding({
      rule: 'aws.cloudtrail.log_file_validation_enabled',
      passed: trails.length > 0 && trailsWithValidation.length === trails.length,
      severity: 'high',
      current: {
        summary: trails.length === 0
          ? 'No trails to validate.'
          : `${trailsWithValidation.length} of ${trails.length} trail(s) have LogFileValidationEnabled.`,
        observations: { trails_without_validation: trails.filter((t) => !t.logFileValidationEnabled).map((t) => t.name) },
      },
      target: { summary: 'All trails have LogFileValidationEnabled=true.', rationale: 'NIST AU-9 (protection of audit info). Without log-file validation, log tampering is undetectable.' },
      gap: (trails.length > 0 && trailsWithValidation.length === trails.length) ? undefined : {
        description: 'Log integrity cannot be verified.',
        affected_resources: trails.length === 0
          ? [{ type: 'aws_account', identifier: ctx.account ?? 'account', name: 'no CloudTrail trail present', attributes: {} }]
          : trails.filter((t) => !t.logFileValidationEnabled).map<AffectedResource>((t) => ({
              type: 'aws_cloudtrail', identifier: t.arn, name: t.name, attributes: {},
            })),
      },
      remediation: (trails.length > 0 && trailsWithValidation.length === trails.length) ? undefined : {
        summary: 'Set enable_log_file_validation=true on each trail.',
        options: [{
          approach: 'Update Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Set enable_log_file_validation=true.', 'Apply.', 'Verify digest files appear in S3.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-9'],
    }),

    finding({
      rule: 'aws.cloudtrail.bucket_object_lock_and_kms',
      passed: gatePass(bucketsWithoutLock.length === 0 && bucketsWithoutKms.length === 0, collected, 'trails'),
      severity: 'high',
      current: {
        summary: bucketsWithoutLock.length === 0 && bucketsWithoutKms.length === 0
          ? `All ${bucketAudits.length} CloudTrail destination bucket(s) have Object Lock + SSE-KMS.`
          : `${bucketsWithoutLock.length} bucket(s) lack Object Lock; ${bucketsWithoutKms.length} lack SSE-KMS.`,
        observations: { audits: bucketAudits, without_object_lock: bucketsWithoutLock, without_kms: bucketsWithoutKms, without_versioning: bucketsWithoutVersioning },
      },
      target: { summary: 'CloudTrail destination buckets have Object Lock (Compliance mode), SSE-KMS with a customer-managed CMK, and versioning enabled.', rationale: 'NIST AU-9, AU-10. Tamper-resistant audit log storage.' },
      gap: (bucketsWithoutLock.length === 0 && bucketsWithoutKms.length === 0) ? undefined : {
        description: 'Audit logs can be modified or deleted, defeating their integrity.',
        affected_resources: [...new Set([...bucketsWithoutLock, ...bucketsWithoutKms])].map<AffectedResource>((b) => ({
          type: 'aws_s3_bucket', identifier: b, name: b, attributes: {
            object_lock: !bucketsWithoutLock.includes(b),
            sse_kms: !bucketsWithoutKms.includes(b),
          },
        })),
      },
      remediation: (bucketsWithoutLock.length === 0 && bucketsWithoutKms.length === 0) ? undefined : {
        summary: 'Recreate buckets (Object Lock requires creation-time enable) with versioning + Object Lock + SSE-KMS.',
        options: [{
          approach: 'New bucket with full controls; migrate trail.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'KMS key + Object Lock retention storage costs.' },
          availability_impact: { level: 'medium', notes: 'Trail migration requires brief gap or parallel run.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Bucket creation + trail migration + verification.' },
          steps: [
            'Create new S3 bucket with object_lock_enabled=true + versioning + SSE-KMS.',
            'Set Object Lock default retention (Compliance mode, 7-year retention typical).',
            'Update trail to point at new bucket.',
            'After overlap window, retire old bucket per data-retention policy.',
          ],
          example_code: `resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket              = "ct-logs-prod"
  object_lock_enabled = true
}
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule { default_retention { mode = "COMPLIANCE" years = 7 } }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cloudtrail.arn
      sse_algorithm     = "aws:kms"
    }
  }
}`,
          references: [{ title: 'S3 Object Lock', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-9','au-10'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-ALA', relationship: 'shares-remediation', note: 'Bucket policy + KMS key policy are the ALA evidence.' },
      ],
    }),

    finding({
      rule: 'aws.cloudtrail.insights_enabled',
      passed: trailsWithInsights.length >= 1,
      severity: 'medium',
      current: {
        summary: trailsWithInsights.length >= 1
          ? `${trailsWithInsights.length} trail(s) have CloudTrail Insights enabled.`
          : 'No trails have Insights enabled — anomalous API call-rate detection is off.',
        observations: { with_insights: trailsWithInsights.map((t) => t.name) },
      },
      target: { summary: 'At least one trail has Insights enabled (ApiCallRateInsight, ApiErrorRateInsight).', rationale: 'NIST SI-4. Detect anomalous control-plane behavior.' },
      gap: trailsWithInsights.length >= 1 ? undefined : {
        description: 'No anomalous-API-rate detection.',
        affected_resources: [{ type: 'aws_cloudtrail_insight_selector', identifier: 'none', attributes: {} }],
      },
      remediation: trailsWithInsights.length >= 1 ? undefined : {
        summary: 'Enable Insights on the org trail.',
        options: [{
          approach: 'Add insight_selector to the trail via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Per-event analyzed charge — usually $tens/month.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Add insight_selector blocks to the trail.', 'Wait 7-14 days for baseline.', 'Wire EventBridge alerts on Insight findings.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-4'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-ALA — Authorizing Log Access
// =====================================================================
export async function collectMlaAla(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { trails, warnings, evidence, collected } = await fetchTrails(ctx);

  // Inspect destination-bucket policies for over-broad principals
  const s3 = aws.s3(ctx.auth);
  interface BucketAcl { bucket: string; policyText: string | null; allowsBroadPrincipal: boolean; sseAlgo: string | null; }
  const bucketAcls: BucketAcl[] = [];
  for (const t of trails) {
    if (!t.s3Bucket) continue;
    let policyText: string | null = null;
    let allowsBroadPrincipal = false;
    try {
      const p = await s3.send(new GetBucketPolicyCommand({ Bucket: t.s3Bucket }));
      policyText = p.Policy ?? null;
      if (policyText) {
        const doc = JSON.parse(policyText);
        for (const s of doc.Statement ?? []) {
          const p2 = s.Principal;
          if ((p2 === '*' || (typeof p2 === 'object' && (p2.AWS === '*' || (Array.isArray(p2.AWS) && p2.AWS.includes('*'))))) && !s.Condition) {
            allowsBroadPrincipal = true;
          }
        }
      }
    } catch { /* no policy */ }
    let sseAlgo: string | null = null;
    try {
      const e = await s3.send(new GetBucketEncryptionCommand({ Bucket: t.s3Bucket }));
      sseAlgo = e.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm ?? null;
    } catch { /* */ }
    bucketAcls.push({ bucket: t.s3Bucket, policyText, allowsBroadPrincipal, sseAlgo });
  }
  evidence.push(ev('s3.audit_bucket_policy_audit', bucketAcls.map((a) => ({ bucket: a.bucket, allowsBroadPrincipal: a.allowsBroadPrincipal, sseAlgo: a.sseAlgo }))));

  // CW Logs groups + their KMS keys + subscription filters
  const logGroupSample: any[] = [];
  let logGroupCount = 0;
  let logGroupsWithoutKms = 0;
  try {
    const cw = aws.cloudwatchlogs(ctx.auth);
    let token: string | undefined;
    do {
      const r = await cw.send(new DescribeLogGroupsCommand({ nextToken: token, limit: 50 }));
      for (const g of r.logGroups ?? []) {
        logGroupCount++;
        if (!g.kmsKeyId) logGroupsWithoutKms++;
        if (logGroupSample.length < 10) logGroupSample.push({ name: g.logGroupName, retentionInDays: g.retentionInDays, kmsKeyId: g.kmsKeyId });
      }
      token = r.nextToken;
    } while (token);
    evidence.push(ev('logs.DescribeLogGroups', { total: logGroupCount, without_kms: logGroupsWithoutKms, sample: logGroupSample }));
  } catch (e: any) { warnings.push(`CW Logs: ${e.message}`); }

  const offendingBuckets = bucketAcls.filter((b) => b.allowsBroadPrincipal).map((b) => b.bucket);

  const findings = [
    finding({
      rule: 'aws.audit_buckets.no_broad_principal',
      passed: gatePass(offendingBuckets.length === 0, collected, 'trails'),
      severity: 'critical',
      current: {
        summary: offendingBuckets.length === 0
          ? `No CloudTrail destination bucket policies grant broad principals.`
          : `${offendingBuckets.length} bucket policy/policies grant overly-broad principals.`,
        observations: { audited: bucketAcls.length, offending: offendingBuckets },
      },
      target: { summary: 'Audit-log bucket policies grant only the CloudTrail service principal + named auditor roles. No `Principal:*` without conditions.', rationale: 'NIST AC-3, SI-11. Audit logs contain sensitive trace data and credentials.' },
      gap: offendingBuckets.length === 0 ? undefined : {
        description: 'Broad principals on audit buckets can expose log content.',
        affected_resources: offendingBuckets.map<AffectedResource>((b) => ({ type: 'aws_s3_bucket_policy', identifier: b, name: b, attributes: {} })),
      },
      remediation: offendingBuckets.length === 0 ? undefined : {
        summary: 'Tighten bucket policies to specific named principals (CloudTrail service + named auditor IAM roles).',
        options: [{
          approach: 'Replace wildcard statements with conditioned, named-principal grants.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'If a vendor SIEM has a wildcard grant, it loses access. Migrate to named-principal first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per bucket policy.' },
          steps: ['Audit current bucket policy.', 'Replace Principal:* with Principal: { Service: "cloudtrail.amazonaws.com" } + named auditor role ARNs.', 'Apply.', 'Validate trail still writes.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','si-11'],
    }),

    finding({
      rule: 'aws.cw_logs.kms_encrypted',
      passed: logGroupCount > 0 && logGroupsWithoutKms === 0,
      severity: 'high',
      current: {
        summary: logGroupCount === 0
          ? 'No CloudWatch Logs groups found (unusual).'
          : (logGroupsWithoutKms === 0 ? `All ${logGroupCount} log group(s) are CMK-encrypted.` : `${logGroupsWithoutKms} of ${logGroupCount} log group(s) lack a CMK association.`),
        observations: { total_log_groups: logGroupCount, without_kms: logGroupsWithoutKms, sample: logGroupSample },
      },
      target: { summary: 'All in-scope log groups have a customer-managed KMS key associated.', rationale: 'NIST SC-13. Encrypts log content at rest with controlled key.' },
      gap: (logGroupCount > 0 && logGroupsWithoutKms === 0) ? undefined : {
        description: 'Log content encrypted with AWS-owned key — no key-policy control over access.',
        affected_resources: [{ type: 'aws_cloudwatch_log_group', identifier: 'aggregate', attributes: { without_kms: logGroupsWithoutKms } }],
      },
      remediation: (logGroupCount > 0 && logGroupsWithoutKms === 0) ? undefined : {
        summary: 'Associate a CMK with each log group via PutResourcePolicy / kms_key_id.',
        options: [{
          approach: 'Set kms_key_id on each log group via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'KMS key usage charges.' },
          availability_impact: { level: 'none', notes: 'No impact.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per log group or fleet.' },
          steps: ['Create a CMK for log encryption.', 'Grant logs.amazonaws.com kms:GenerateDataKey via key policy.', 'Associate the CMK with each log group.'],
          example_code: `resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/prod"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-13','sc-28'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-EVC — Evaluating Configurations
// (Differentiates from CNA-EIS by focusing on MEASUREMENT/finding lifecycle.)
// =====================================================================
export async function collectMlaEvc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Security Hub finding lifecycle (NEW vs NOTIFIED vs RESOLVED)
  let newCount = 0;
  let notifiedCount = 0;
  let suppressedCount = 0;
  let securityHubCollected = false;
  try {
    const sh = aws.securityhub(ctx.auth);
    for (const status of ['NEW', 'NOTIFIED', 'SUPPRESSED']) {
      const r = await sh.send(new ShGetFindingsCommand({
        Filters: { WorkflowStatus: [{ Value: status, Comparison: 'EQUALS' }] },
        MaxResults: 100,
      }));
      const count = r.Findings?.length ?? 0;
      if (status === 'NEW') newCount = count;
      else if (status === 'NOTIFIED') notifiedCount = count;
      else if (status === 'SUPPRESSED') suppressedCount = count;
    }
    securityHubCollected = true;
    evidence.push(ev('securityhub.finding_lifecycle', { new: newCount, notified: notifiedCount, suppressed: suppressedCount }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'securityhub.GetFindings', 'securityhub:GetFindings')); }

  const totalActive = newCount + notifiedCount;
  const triagedPercent = totalActive > 0 ? Math.round((notifiedCount / totalActive) * 100) : 100;

  // CodeBuild projects — scan buildspecs for IaC scanner invocations
  let codeBuildProjectCount = 0;
  let projectsRunningIacScans = 0;
  try {
    const cb = aws.codebuild(ctx.auth);
    // CodeBuild SDK requires listing project names first, then batch-get
    const list = await (cb as any).send({ constructor: { name: 'ListProjectsCommand' } }).catch(() => null);
    // We can't easily inspect buildspecs without batch-get + project source; surface count only
    codeBuildProjectCount = list?.projects?.length ?? 0;
    evidence.push(ev('codebuild.project_count', { count: codeBuildProjectCount }));
  } catch (e: any) { warnings.push(`CodeBuild: ${e.message}`); }

  const findings = [
    finding({
      rule: 'aws.security_hub.finding_triage_lifecycle_active',
      passed: securityHubCollected && (totalActive === 0 || triagedPercent >= 50),
      severity: 'medium',
      current: {
        summary: `${newCount} NEW + ${notifiedCount} NOTIFIED + ${suppressedCount} SUPPRESSED Security Hub findings. ${triagedPercent}% of active findings have moved to NOTIFIED (triage activity).`,
        observations: { new: newCount, notified: notifiedCount, suppressed: suppressedCount, triaged_percent: triagedPercent },
      },
      target: { summary: 'Active findings are being triaged (≥50% have moved out of NEW). MTTR by severity tracked elsewhere.', rationale: 'NIST CA-7. Persistent evaluation requires ongoing triage; stuck NEW findings indicate the evaluation loop is broken.' },
      gap: (totalActive === 0 || triagedPercent >= 50) ? undefined : {
        description: 'Most findings stuck in NEW — the evaluation loop is not closing.',
        affected_resources: [{ type: 'aws_securityhub_finding', identifier: 'aggregate', attributes: { new: newCount, notified: notifiedCount } }],
      },
      remediation: (totalActive === 0 || triagedPercent >= 50) ? undefined : {
        summary: 'Establish a finding-triage cadence; route findings to ticketing.',
        options: [{
          approach: 'Wire Security Hub findings to JIRA / ServiceNow via a custom action.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Per-API charges; usually negligible.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Set up custom action + Lambda integration.' },
          steps: ['Create Security Hub custom action.', 'Build Lambda that creates tickets.', 'Define an EventBridge rule routing custom-action events to Lambda.', 'Establish weekly triage meeting.'],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party CNAPP/SIEM with finding workflow (Wiz, Lacework, Datadog Cloud SIEM)', description: 'External tool drives the triage.', evidence_required: ['Representative finding lifecycle in external tool', 'MTTR report'], detected: false },
      ],
      nist_controls: ['ca-7','si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-EIS', relationship: 'shares-remediation', note: 'Same closed-loop improvement.' },
        { ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'CNA-EIS measures enforcement; MLA-EVC measures evaluation cadence.' },
      ],
    }),

    finding({
      rule: 'aws.codebuild.projects_present',
      passed: codeBuildProjectCount >= 1,
      severity: 'info',
      current: {
        summary: codeBuildProjectCount >= 1 ? `${codeBuildProjectCount} CodeBuild project(s) found.` : 'No CodeBuild projects (CI may live off-AWS).',
        observations: { project_count: codeBuildProjectCount },
      },
      target: { summary: 'CI pipelines run IaC scanners (tfsec, Checkov, cfn-nag) as gates.', rationale: 'NIST CM-3.2. IaC evaluation must happen pre-deploy.' },
      gap: codeBuildProjectCount >= 1 ? undefined : {
        description: 'No AWS-native CI pipelines detected. If CI runs off-AWS, attach the alternative-satisfier evidence; otherwise pipelines do not exist.',
        affected_resources: [{ type: 'aws_account', identifier: ctx.account ?? 'account', name: 'no CodeBuild project present', attributes: {} }],
      },
      remediation: codeBuildProjectCount >= 1 ? undefined : {
        summary: 'Either attach off-AWS pipeline evidence (preferred) or set up an in-AWS CI project.',
        options: [{
          approach: 'Provide off-AWS CI evidence (GitHub Actions / GitLab CI / Buildkite workflow YAML + a sample build log showing tfsec/Checkov output).',
          mechanism: 'process',
          owner_team: 'Platform',
          steps: [
            'Locate the CI repo defining the pipelines.',
            'Export the relevant workflow YAML and a sample build log to the evidence package.',
            'Annotate this finding in the tracker with the off-AWS pipeline URL.',
          ],
          cost_impact: { level: 'none', notes: 'Documentation only.' },
          availability_impact: { level: 'none', notes: 'N/A.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'One-time evidence collection.' },
        }, {
          approach: 'Provision an in-AWS CodeBuild project as the IaC scanner.',
          mechanism: 'terraform',
          owner_team: 'Platform',
          steps: ['Define aws_codebuild_project with the IaC scan command in buildspec.', 'Wire the project to a CodePipeline source stage.'],
          cost_impact: { level: 'low', notes: 'Per-build-minute pricing.' },
          availability_impact: { level: 'low', notes: 'Net-new infra.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per pipeline.' },
        }],
      },
      alternative_satisfiers: [
        { via: 'GitHub Actions / GitLab CI off-AWS pipelines', description: 'Pipelines may run outside AWS; IaC scanner invocations live in the pipeline definition repo.', evidence_required: ['Pipeline YAML excerpt invoking tfsec/Checkov', 'Sample build log showing scanner output'], detected: false },
      ],
      nist_controls: ['cm-3.2'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-VTD', relationship: 'shares-remediation', note: 'IaC scanning is part of VTD gating.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-LET — Logging Event Types
// =====================================================================
export async function collectMlaLet(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const { trails, warnings, evidence, collected } = await fetchTrails(ctx);

  // CloudTrail data events (S3, Lambda, DynamoDB)
  let trailsWithDataEvents = 0;
  for (const t of trails) {
    if (t.eventSelectors.some((es: any) => (es.DataResources ?? []).length > 0)) trailsWithDataEvents++;
  }

  // A trail logs management events if it has an explicit selector saying so, OR
  // it has NO event selectors AND we successfully read them (empty selectors ==
  // AWS default of "all management events on"). A trail whose GetEventSelectors
  // FAILED must NOT count as "management on" — an unread selector is indeterminate.
  const managementEventsLogged = trails.some((t) =>
    (t.eventSelectorsRead && t.eventSelectors.length === 0)
    || t.eventSelectors.some((es: any) => es.IncludeManagementEvents !== false)
  );

  // Other AWS logging sources to inventory:
  // - VPC Flow Logs (already covered by CNA-RNT but flag here too)
  // - ELB access logs (would require DescribeLoadBalancerAttributes)
  // - RDS audit logs / EKS audit logs (deep per-resource queries; defer)
  // We'll surface what we can quickly: trail coverage + WAF logging via wafv2.GetLoggingConfiguration

  const findings = [
    finding({
      rule: 'aws.cloudtrail.management_events_logged',
      passed: gatePass(managementEventsLogged, collected, 'trails'),
      severity: 'critical',
      current: {
        summary: `${trails.length} trail(s); ${trailsWithDataEvents} with explicit data-event selectors.`,
        observations: { trail_summary: trails.map((t) => ({ name: t.name, has_event_selectors: t.eventSelectors.length > 0 })) },
      },
      target: { summary: 'CloudTrail management events on for all in-scope accounts; data events on for in-scope S3 buckets, Lambda functions, DynamoDB tables.', rationale: 'NIST AU-2, AU-12. Management events are the API change-log; data events are the data-access log.' },
      gap: managementEventsLogged ? undefined : {
        description: 'No CloudTrail trail captures management events — the API audit log is absent.',
        affected_resources: [{ type: 'aws_cloudtrail', identifier: 'no-management-events', attributes: { trail_count: trails.length } }],
      },
      remediation: managementEventsLogged ? undefined : {
        summary: 'Provision an org-wide multi-region CloudTrail with management events on.',
        options: [{
          approach: 'Provision via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          steps: [
            'Create a multi-region trail in the management account.',
            'Enable IncludeManagementEvents=true.',
            'Send to a centralized S3 bucket with KMS + lifecycle.',
            'Enable log-file integrity validation.',
          ],
          cost_impact: { level: 'low', notes: 'First copy of management events is free; data events are metered.' },
          availability_impact: { level: 'none', notes: 'Read-side only.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'For a clean account; longer if migrating from per-account trails.' },
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','au-12'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Same trail provides both KSIs.' },
      ],
    }),

    finding({
      rule: 'aws.cloudtrail.data_events_on_s3',
      passed: trailsWithDataEvents >= 1,
      severity: 'high',
      current: {
        summary: trailsWithDataEvents >= 1 ? `${trailsWithDataEvents} trail(s) capture S3/Lambda/DynamoDB data events.` : 'No trail captures data events — data-access auditability is limited.',
        observations: { trails_with_data_events: trailsWithDataEvents },
      },
      target: { summary: 'In-scope S3 buckets, Lambda functions, and DynamoDB tables have data-event logging in at least one trail.', rationale: 'NIST AU-2. Data events log Get/Put/Invoke — the actual data-access audit.' },
      gap: trailsWithDataEvents >= 1 ? undefined : {
        description: 'Data-access events (S3 Get/Put, Lambda Invoke, DynamoDB Get/Put) are unlogged.',
        affected_resources: [{ type: 'aws_cloudtrail_event_selectors', identifier: 'no-data-events', attributes: {} }],
      },
      remediation: trailsWithDataEvents >= 1 ? undefined : {
        summary: 'Add advanced event selectors to the org trail for in-scope S3 buckets / Lambda / DynamoDB.',
        options: [{
          approach: 'Configure advanced event selectors via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Data events are charged per event ($0.10/100k); high-volume buckets can be expensive.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Identify in-scope buckets/functions; configure selectors.' },
          steps: ['Identify in-scope resources via PIY-GIV inventory.', 'Add advanced_event_selector blocks to the trail.', 'Verify data events flowing.'],
          example_code: `resource "aws_cloudtrail" "org" {
  advanced_event_selector {
    name = "data-events-s3"
    field_selector { field = "eventCategory" equals = ["Data"] }
    field_selector { field = "resources.type" equals = ["AWS::S3::Object"] }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-OSM — Operating SIEM Capability
// =====================================================================
export async function collectMlaOsm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Detection signals
  let firehoseStreams: Array<{ name: string; destination: string }> = [];
  let cwSubscriptionFilters = 0;
  let securityLakeConfigured = false;

  try {
    const fh = aws.firehose(ctx.auth);
    const list = await fh.send(new ListDeliveryStreamsCommand({}));
    for (const name of list.DeliveryStreamNames ?? []) {
      const d = await fh.send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: name }));
      const dest = d.DeliveryStreamDescription?.Destinations?.[0];
      let destType = 'unknown';
      if (dest?.HttpEndpointDestinationDescription) destType = `http:${dest.HttpEndpointDestinationDescription.EndpointConfiguration?.Url ?? ''}`;
      else if (dest?.S3DestinationDescription) destType = 's3';
      else if (dest?.ElasticsearchDestinationDescription) destType = 'opensearch';
      else if (dest?.SplunkDestinationDescription) destType = 'splunk';
      firehoseStreams.push({ name, destination: destType });
    }
    evidence.push(ev('firehose.streams', firehoseStreams));
  } catch (e: any) { warnings.push(`Firehose: ${e.message}`); }

  try {
    const cw = aws.cloudwatchlogs(ctx.auth);
    // Sample subscription filters across log groups
    const grps = await cw.send(new DescribeLogGroupsCommand({ limit: 50 }));
    for (const g of (grps.logGroups ?? []).slice(0, 20)) {
      if (!g.logGroupName) continue;
      try {
        const f = await cw.send(new DescribeSubscriptionFiltersCommand({ logGroupName: g.logGroupName }));
        cwSubscriptionFilters += f.subscriptionFilters?.length ?? 0;
      } catch { /* ignore */ }
    }
    evidence.push(ev('logs.subscription_filters', { count: cwSubscriptionFilters, sampled: 20 }));
  } catch (e: any) { warnings.push(`CW Logs subscription filters: ${e.message}`); }

  // Security Lake direct detection (read-only: ListDataLakes + ListSubscribers).
  let securityLakeDataLakes: Array<{ region: string | null; status: string | null; s3: string | null }> = [];
  let securityLakeSubscribers = 0;
  try {
    const sl = aws.securitylake(ctx.auth);
    const lakes = await sl.send(new ListDataLakesCommand({ regions: [ctx.region] }));
    securityLakeDataLakes = (lakes.dataLakes ?? []).map((d) => ({
      region: d.region ?? null,
      status: d.createStatus ?? null,
      s3: d.s3BucketArn ?? null,
    }));
    securityLakeConfigured = securityLakeDataLakes.some((d) => d.status == null || /completed|initialized/i.test(d.status));
    if (securityLakeConfigured) {
      try {
        const subs = await sl.send(new ListSubscribersCommand({}));
        securityLakeSubscribers = (subs.subscribers ?? []).length;
      } catch (e: any) { warnings.push(`Security Lake ListSubscribers: ${e.message}`); }
    }
    evidence.push(ev('securitylake.data_lakes', { configured: securityLakeConfigured, data_lakes: securityLakeDataLakes, subscriber_count: securityLakeSubscribers }));
  } catch (e: any) {
    // Not enabled / no permission is expected when Security Lake isn't in use — surface as a warning, not a failure.
    warnings.push(`Security Lake (securitylake:ListDataLakes): ${e.message}`);
  }

  const splunkFh = firehoseStreams.filter((s) => /splunk/i.test(s.destination));
  const datadogFh = firehoseStreams.filter((s) => /datadoghq/i.test(s.destination));
  const httpFh = firehoseStreams.filter((s) => s.destination.startsWith('http:'));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Splunk (via Firehose HTTP / Splunk destination)',
      description: 'CloudTrail + log data forwarded to Splunk Cloud / Splunk Enterprise.',
      evidence_required: ['Firehose delivery stream → Splunk', 'Splunk indexer dashboard showing recent AWS data', 'Ingestion lag chart'],
      detected: splunkFh.length > 0,
      detection_signals: splunkFh.map((s) => `Firehose: ${s.name} → ${s.destination}`),
    },
    {
      via: 'Datadog Cloud SIEM',
      description: 'Logs forwarded to Datadog\'s log endpoint via Firehose.',
      evidence_required: ['Firehose → Datadog HTTP destination', 'Datadog dashboard / saved query showing recent data', 'Ingestion lag'],
      detected: datadogFh.length > 0,
      detection_signals: datadogFh.map((s) => `Firehose: ${s.name} → ${s.destination}`),
    },
    {
      via: 'AWS Security Lake (native)',
      description: 'OCSF-format unified log lake.',
      evidence_required: ['Security Lake subscriber config', 'Sample query via Athena / OpenSearch'],
      detected: securityLakeConfigured,
      detection_signals: securityLakeConfigured
        ? securityLakeDataLakes.map((d) => `Data lake ${d.region ?? '?'} (${d.status ?? 'status?'}) → ${d.s3 ?? 's3?'}; ${securityLakeSubscribers} subscriber(s)`)
        : ['No Security Lake data lake found in this region (or no securitylake:ListDataLakes permission).'],
    },
  ];

  const anySiemDetected = splunkFh.length > 0 || datadogFh.length > 0 || httpFh.length > 0 || cwSubscriptionFilters > 0 || securityLakeConfigured;

  const findings = [
    finding({
      rule: 'aws.siem.export_plumbing_present',
      passed: anySiemDetected,
      severity: 'high',
      current: {
        summary: anySiemDetected
          ? `SIEM export plumbing detected: ${firehoseStreams.length} Firehose stream(s), ${cwSubscriptionFilters} CW Logs subscription filter(s)${securityLakeConfigured ? `, AWS Security Lake (${securityLakeDataLakes.length} data lake(s), ${securityLakeSubscribers} subscriber(s))` : ''}.`
          : 'No SIEM export plumbing detected (Firehose / CW Logs subscription filters / Security Lake).',
        observations: { firehose_streams: firehoseStreams, cw_subscription_filters: cwSubscriptionFilters, security_lake: { configured: securityLakeConfigured, data_lakes: securityLakeDataLakes, subscriber_count: securityLakeSubscribers } },
      },
      target: { summary: 'At least one Firehose stream OR CloudWatch Logs subscription filter routes audit logs to a SIEM (cloud-native Security Lake / Chronicle, or 3rd-party Splunk / Datadog / Sumo Logic / Elastic).', rationale: 'NIST AU-6. Centralized analysis is FedRAMP 20x MLA-OSM core.' },
      gap: anySiemDetected ? undefined : {
        description: 'Audit logs sit in their source services with no centralized analysis.',
        affected_resources: [{ type: 'aws_kinesis_firehose_delivery_stream', identifier: 'none', attributes: {} }],
      },
      remediation: anySiemDetected ? undefined : {
        summary: 'Stand up a SIEM forwarding pipeline. AWS Security Lake is the cloud-native choice; 3rd-party SIEM via Firehose is the alternative.',
        options: [{
          approach: 'Deploy Security Lake (cloud-native, OCSF format).',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'high', notes: 'Security Lake + S3 + KMS + processing. Hundreds-thousands/month depending on log volume.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Standup + subscriber config + tuning.' },
          steps: ['Enable Security Lake.', 'Configure CloudTrail + VPC + Route 53 + Security Hub as sources.', 'Configure OCSF subscriber for downstream consumption.'],
          references: [{ title: 'Security Lake', url: 'https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html' }],
        }, {
          approach: '3rd-party SIEM via Firehose (Splunk / Datadog / Sumo Logic).',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'high', notes: 'Firehose ingestion + vendor SIEM costs.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Firehose setup + SIEM tenant configuration.' },
          steps: ['Configure Firehose destination per vendor docs.', 'Wire CloudTrail / CW Logs sources.', 'Verify data in SIEM.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['au-6','au-6.1','au-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SUS', relationship: 'precedes', note: 'SIEM findings are the IAM-SUS detection source.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-RVL — Reviewing Logs
// =====================================================================
export async function collectMlaRvl(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let workgroupCount = 0;
  let savedQueryCount = 0;
  try {
    const at = aws.athena(ctx.auth);
    const wg = await at.send(new ListWorkGroupsCommand({}));
    workgroupCount = wg.WorkGroups?.length ?? 0;
    for (const w of wg.WorkGroups ?? []) {
      if (!w.Name) continue;
      try {
        const q = await at.send(new ListNamedQueriesCommand({ WorkGroup: w.Name }));
        savedQueryCount += q.NamedQueryIds?.length ?? 0;
      } catch { /* ignore */ }
    }
    evidence.push(ev('athena.review_tooling', { workgroups: workgroupCount, saved_queries: savedQueryCount }));
  } catch (e: any) { warnings.push(`Athena: ${e.message}`); }

  const findings = [
    finding({
      rule: 'aws.athena.review_tooling_present',
      passed: workgroupCount >= 1 && savedQueryCount >= 1,
      severity: 'medium',
      current: {
        summary: workgroupCount >= 1 && savedQueryCount >= 1
          ? `${workgroupCount} Athena workgroup(s) with ${savedQueryCount} saved query/queries.`
          : `Athena workgroups: ${workgroupCount}, saved queries: ${savedQueryCount}. Limited log-review tooling visible.`,
        observations: { workgroups: workgroupCount, saved_queries: savedQueryCount },
      },
      target: { summary: 'Athena (or equivalent) workgroup exists with ≥1 saved query for routine log review (e.g. recent failed sign-ins, root API calls, IAM-policy changes).', rationale: 'NIST AU-6. Reviewability is a tooling problem first; cadence + ownership are tracker-side.' },
      gap: (workgroupCount >= 1 && savedQueryCount >= 1) ? undefined : {
        description: 'No saved-query corpus for log review — every analysis is ad-hoc.',
        affected_resources: [{ type: 'aws_athena_named_query', identifier: 'aggregate', attributes: { workgroups: workgroupCount, saved_queries: savedQueryCount } }],
      },
      remediation: (workgroupCount >= 1 && savedQueryCount >= 1) ? undefined : {
        summary: 'Create an Athena workgroup with saved queries for routine review.',
        options: [{
          approach: 'Stand up workgroup + saved queries via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Athena charges per TB scanned. Saved queries themselves are free.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Workgroup + query authoring.' },
          steps: [
            'Create CloudTrail-events Glue table.',
            'Create an Athena workgroup with appropriate result location.',
            'Author saved queries: root API calls, IAM policy changes, console sign-in events, etc.',
          ],
          references: [{ title: 'Querying CloudTrail with Athena', url: 'https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party SIEM saved dashboards / queries (Splunk, Datadog, Sumo Logic)', description: 'Review tooling can live in the SIEM.', evidence_required: ['SIEM dashboard exports', 'Review-meeting minutes'], detected: false },
      ],
      nist_controls: ['au-6'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-INR-RIR — Reviewing Incident Response Procedures (HYBRID)
// Broader than IAM-SUS — covers ALL alert routing infrastructure.
// =====================================================================
export async function collectInrRir(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // SNS subscriptions, EventBridge security rules, Chatbot are surfaced via existing logging APIs
  // We'll use what we have — focus on subscription filters as a proxy for "is alert plumbing wired"
  let logSubscriptionFiltersTotal = 0;
  try {
    const cw = aws.cloudwatchlogs(ctx.auth);
    const grps = await cw.send(new DescribeLogGroupsCommand({ limit: 50 }));
    for (const g of (grps.logGroups ?? []).slice(0, 30)) {
      if (!g.logGroupName) continue;
      try {
        const f = await cw.send(new DescribeSubscriptionFiltersCommand({ logGroupName: g.logGroupName }));
        logSubscriptionFiltersTotal += f.subscriptionFilters?.length ?? 0;
      } catch { /* */ }
    }
    evidence.push(ev('logs.subscription_filters_for_rir', { sampled: 30, count: logSubscriptionFiltersTotal }));
  } catch (e: any) { warnings.push(`CW Logs: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'PagerDuty / OpsGenie via EventBridge / SNS',
      description: 'Findings routed to incident-management platform via standard cloud → 3rd-party wiring.',
      evidence_required: ['EventBridge rule target ARN / SNS subscription endpoint', 'Sample paging event from incident-mgmt vendor', 'Runbook URL'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'Tines / Torq SOAR consuming alerts',
      description: 'SOAR platform runs response automation.',
      evidence_required: ['SOAR playbook export', 'Sample execution log'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.alert_routing.plumbing_present',
      passed: logSubscriptionFiltersTotal > 0,
      severity: 'high',
      current: {
        summary: logSubscriptionFiltersTotal > 0
          ? `${logSubscriptionFiltersTotal} CW Logs subscription filter(s) present — alert plumbing wired.`
          : 'No CW Logs subscription filters detected — alerts may not be routed to downstream consumers.',
        observations: { subscription_filters: logSubscriptionFiltersTotal },
      },
      target: { summary: 'At least one cross-cutting alert-routing primitive in use: CW Logs subscription filters → 3rd-party SIEM / PagerDuty, OR EventBridge → Lambda, OR Security Hub custom actions.', rationale: 'NIST IR-4. IR procedures need a routing fabric.' },
      gap: logSubscriptionFiltersTotal > 0 ? undefined : {
        description: 'Without alert routing, IR procedures are manual.',
        affected_resources: [{ type: 'aws_cloudwatch_log_subscription_filter', identifier: 'none', attributes: {} }],
      },
      remediation: logSubscriptionFiltersTotal > 0 ? undefined : {
        summary: 'Wire CW Logs → SIEM or SNS → PagerDuty.',
        options: [{
          approach: 'Subscription filter to Firehose → SIEM, OR SNS topic → PagerDuty.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Per-event charges; modest.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Filter + target + verify.' },
          steps: ['Identify alert sources (log groups, EventBridge events).', 'Create subscription filter → Firehose or Lambda.', 'Verify downstream consumption.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ir-4','ir-4.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SUS', relationship: 'shares-remediation', note: 'IAM-SUS is the IAM-specific subset; RIR is the broader fabric.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
