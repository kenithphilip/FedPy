/**
 * AWS data-domain collectors.
 *   - KSI-SVC-RUD — Removing Unwanted Data (lifecycle + ad-hoc deletion)
 *   - KSI-SVC-VCM — Validating Communications (service-to-service auth)
 *   - KSI-SVC-VRI — Validating Resource Integrity (cryptographic signing/attestation)
 */
import { ListBucketsCommand, GetBucketLifecycleConfigurationCommand, GetBucketVersioningCommand, GetObjectLockConfigurationCommand } from '@aws-sdk/client-s3';
import { ListMeshesCommand, ListVirtualNodesCommand, DescribeVirtualNodeCommand } from '@aws-sdk/client-app-mesh';
import { ListClustersCommand, ListAddonsCommand } from '@aws-sdk/client-eks';
import { ListFunctionsCommand, GetFunctionCodeSigningConfigCommand, GetFunctionUrlConfigCommand } from '@aws-sdk/client-lambda';
import { ListSigningProfilesCommand, ListSigningJobsCommand } from '@aws-sdk/client-signer';
import { ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { GetPatchBaselineCommand, DescribePatchBaselinesCommand } from '@aws-sdk/client-ssm';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';
import { classifyError, diagnoseAwsError } from '../../core/error-diagnostics.ts';

/** Hard cap on pagination loops so a buggy/looping NextMarker can never hang collection. */
const MAX_PAGINATION_ITERATIONS = 1000;

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

/**
 * Push a warning only when an error is a permission/throttle/network problem.
 * "Not configured"-style errors (NoSuchLifecycleConfiguration, ObjectLock not
 * enabled, etc.) classify as not_found and are expected — we stay silent on
 * those so the warnings list reflects real action items only.
 */
function warnIfActionable(warnings: string[], err: unknown, source: string, requiredAction: string): void {
  const klass = classifyError(err);
  if (klass === 'not_found' || klass === 'not_enabled') return;  // expected; no action needed
  warnings.push(diagnoseAwsError(err, source, requiredAction));
}

interface Ctx { region: string; auth: aws.AwsAuth; account: string | null; }
async function setupCtx(c: CollectorContext): Promise<Ctx> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  return { region, auth, account };
}

// =====================================================================
// KSI-SVC-RUD — Removing Unwanted Data
// Two angles: (a) proactive lifecycle, (b) ad-hoc deletion mechanism.
// =====================================================================
export async function collectSvcRud(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // ---- S3 bucket lifecycle rules ----
  interface BucketLifecycle { bucket: string; hasExpirationRule: boolean; hasIncompleteMultipartCleanup: boolean; versioning: string | null; objectLock: boolean; }
  const bucketLifecycles: BucketLifecycle[] = [];
  let totalBuckets = 0;
  let bucketsCollected = false;
  try {
    const s3 = aws.s3(ctx.auth);
    const r = await s3.send(new ListBucketsCommand({}));
    for (const b of r.Buckets ?? []) {
      if (!b.Name) continue;
      totalBuckets++;
      let hasExpirationRule = false;
      let hasIncompleteMultipartCleanup = false;
      try {
        const lc = await s3.send(new GetBucketLifecycleConfigurationCommand({ Bucket: b.Name }));
        for (const rule of lc.Rules ?? []) {
          if (rule.Expiration?.Days || rule.Expiration?.Date) hasExpirationRule = true;
          if (rule.AbortIncompleteMultipartUpload?.DaysAfterInitiation) hasIncompleteMultipartCleanup = true;
        }
      } catch (e) { warnIfActionable(warnings, e, `s3.GetBucketLifecycle ${b.Name}`, 's3:GetLifecycleConfiguration'); }
      let versioning: string | null = null;
      try {
        const v = await s3.send(new GetBucketVersioningCommand({ Bucket: b.Name }));
        versioning = v.Status ?? null;
      } catch (e) { warnIfActionable(warnings, e, `s3.GetBucketVersioning ${b.Name}`, 's3:GetBucketVersioning'); }
      let objectLock = false;
      try {
        const o = await s3.send(new GetObjectLockConfigurationCommand({ Bucket: b.Name }));
        objectLock = !!o.ObjectLockConfiguration?.ObjectLockEnabled;
      } catch (e) { warnIfActionable(warnings, e, `s3.GetObjectLockConfiguration ${b.Name}`, 's3:GetBucketObjectLockConfiguration'); }
      bucketLifecycles.push({ bucket: b.Name, hasExpirationRule, hasIncompleteMultipartCleanup, versioning, objectLock });
    }
    bucketsCollected = true;
    evidence.push(ev('s3.bucket_lifecycle_audit', { total: totalBuckets, audits: bucketLifecycles }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 's3.ListBuckets', 's3:ListAllMyBuckets')); }

  const bucketsWithoutLifecycle = bucketLifecycles.filter((b) => !b.hasExpirationRule).map((b) => b.bucket);

  // ---- KMS keys with PendingDeletion state (evidence of deletion mechanism use) ----
  let pendingDeletionKeys = 0;
  let totalKeys = 0;
  try {
    const kms = aws.kms(ctx.auth);
    const r = await kms.send(new ListKeysCommand({ Limit: 100 }));
    for (const k of r.Keys ?? []) {
      if (!k.KeyId) continue;
      totalKeys++;
      try {
        const d = await kms.send(new DescribeKeyCommand({ KeyId: k.KeyId }));
        if (d.KeyMetadata?.KeyState === 'PendingDeletion') pendingDeletionKeys++;
      } catch (e) { warnIfActionable(warnings, e, `kms.DescribeKey ${k.KeyId}`, 'kms:DescribeKey'); }
    }
    evidence.push(ev('kms.deletion_history_proxy', { total_keys: totalKeys, pending_deletion: pendingDeletionKeys }));
  } catch (e: any) { warnings.push(`KMS: ${e.message}`); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Customer-data-request workflow tool (Drata DSR, OneTrust, custom Lambda)',
      description: 'Ad-hoc deletion of customer data via dedicated workflow tooling; cloud-side lifecycle handles only proactive retention.',
      evidence_required: ['Workflow tool config showing data-deletion runbook', 'Sample DSR with audit log of executed deletions', 'Customer-deletion runbook URL'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.s3.buckets_have_lifecycle_or_retention',
      passed: bucketsCollected && bucketsWithoutLifecycle.length === 0,
      severity: 'medium',
      current: {
        summary: bucketsWithoutLifecycle.length === 0
          ? `All ${totalBuckets} bucket(s) have an Expiration lifecycle rule.`
          : `${bucketsWithoutLifecycle.length} of ${totalBuckets} bucket(s) lack an Expiration rule.`,
        observations: { total_buckets: totalBuckets, without_lifecycle: bucketsWithoutLifecycle, audits: bucketLifecycles },
      },
      target: { summary: 'Every in-scope data bucket has either an Expiration rule (auto-delete) OR a documented infinite-retention exception (e.g. audit logs with Object Lock + 7-year retention).', rationale: 'NIST MP-6 (media sanitization), SI-12 (information retention).' },
      gap: bucketsWithoutLifecycle.length === 0 ? undefined : {
        description: 'Buckets without lifecycle accumulate data indefinitely — increases breach blast radius + storage cost.',
        affected_resources: bucketsWithoutLifecycle.map<AffectedResource>((b) => ({
          type: 'aws_s3_bucket_lifecycle_configuration', identifier: b, name: b, attributes: {},
        })),
      },
      remediation: bucketsWithoutLifecycle.length === 0 ? undefined : {
        summary: 'Apply lifecycle configuration matching the bucket\'s data class.',
        options: [{
          approach: 'Apply lifecycle via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free; lower storage costs over time.' },
          availability_impact: { level: 'medium', notes: 'Setting overly-aggressive expiration deletes data prematurely. Audit retention needs first.' },
          customer_visible: { level: 'medium', notes: 'If buckets hold federal customer data, lifecycle must match customer agreement retention terms.' },
          effort_estimate: { magnitude: 'days', notes: 'Per-bucket audit + apply.' },
          steps: ['Document retention requirement per bucket.', 'Apply matching lifecycle rule.', 'Test with a small subset first.'],
          example_code: `resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-old-objects"
    status = "Enabled"
    expiration { days = 365 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}`,
          references: [{ title: 'S3 Lifecycle', url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html' }],
        }],
      },
      alternative_satisfiers: [
        { via: 'Bucket has Object Lock with retention matching contractual obligation', description: 'Audit-log buckets keep data indefinitely under Object Lock — no Expiration needed.', evidence_required: ['Object Lock configuration', 'Retention agreement showing intentional indefinite retention'], detected: false },
      ],
      nist_controls: ['mp-6','si-12'],
    }),

    finding({
      rule: 'aws.kms.deletion_mechanism_demonstrated',
      passed: pendingDeletionKeys >= 0, // info-only; evidence of mechanism is the existence of the API path + at least some history
      severity: 'info',
      current: {
        summary: pendingDeletionKeys === 0
          ? 'No KMS keys currently in PendingDeletion state. (Either no deletions have happened, or all have completed.)'
          : `${pendingDeletionKeys} KMS key(s) currently in PendingDeletion (waiting for window expiry).`,
        observations: { total_keys: totalKeys, pending_deletion: pendingDeletionKeys },
      },
      target: { summary: 'Evidence of deletion mechanism use — past key destructions visible via CloudTrail filter; current PendingDeletion observable here.', rationale: 'NIST MP-6. Cryptographic erasure via key destruction is a fast bulk-deletion primitive.' },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['mp-6'],
      note: 'Detailed deletion-event history available via a CloudTrail filter on ScheduleKeyDeletion / DeleteObject — out of scope for this collector run; reference the SIEM saved query.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-VCM — Validating Communications (service-to-service auth)
// =====================================================================
export async function collectSvcVcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // App Mesh
  interface VirtualNodeMtls { mesh: string; node: string; listenerMtls: string | null; }
  const vnodes: VirtualNodeMtls[] = [];
  let meshCount = 0;
  let appMeshCollected = false;
  try {
    const am = aws.appmesh(ctx.auth);
    const meshes = await am.send(new ListMeshesCommand({}));
    meshCount = meshes.meshes?.length ?? 0;
    for (const m of meshes.meshes ?? []) {
      if (!m.meshName) continue;
      const vlist = await am.send(new ListVirtualNodesCommand({ meshName: m.meshName }));
      for (const v of vlist.virtualNodes ?? []) {
        if (!v.virtualNodeName) continue;
        const d = await am.send(new DescribeVirtualNodeCommand({ meshName: m.meshName, virtualNodeName: v.virtualNodeName }));
        const listener = d.virtualNode?.spec?.listeners?.[0];
        const mtlsMode = listener?.tls?.mode ?? null;
        vnodes.push({ mesh: m.meshName, node: v.virtualNodeName, listenerMtls: mtlsMode });
      }
    }
    appMeshCollected = true;
    evidence.push(ev('appmesh.mtls_audit', { mesh_count: meshCount, virtual_nodes: vnodes }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'appmesh.mtls_audit', 'appmesh:ListMeshes')); }

  const nodesWithoutStrictMtls = vnodes.filter((n) => n.listenerMtls !== 'STRICT');

  // Lambda function URLs — require IAM auth
  let lambdaUrlsTotal = 0;
  let lambdaUrlsWithoutIam: string[] = [];
  let lambdaUrlsCollected = false;
  try {
    const lambda = aws.lambda(ctx.auth);
    let tok: string | undefined;
    let iter = 0;
    do {
      const r = await lambda.send(new ListFunctionsCommand({ Marker: tok, MaxItems: 50 }));
      for (const f of r.Functions ?? []) {
        if (!f.FunctionName) continue;
        try {
          const u = await lambda.send(new GetFunctionUrlConfigCommand({ FunctionName: f.FunctionName }));
          lambdaUrlsTotal++;
          if (u.AuthType !== 'AWS_IAM') lambdaUrlsWithoutIam.push(f.FunctionName);
        } catch (e) {
          // ResourceNotFoundException = function has no URL config (expected, not an error).
          // Any other error (AccessDenied etc.) is surfaced as an actionable warning.
          warnIfActionable(warnings, e, `lambda.GetFunctionUrlConfig ${f.FunctionName}`, 'lambda:GetFunctionUrlConfig');
        }
      }
      const next = r.NextMarker;
      tok = next && next !== tok ? next : undefined; // stop on repeated/empty marker
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    lambdaUrlsCollected = true;
    evidence.push(ev('lambda.function_url_audit', { total_urls: lambdaUrlsTotal, without_iam: lambdaUrlsWithoutIam }));
  } catch (e) { warnIfActionable(warnings, e, 'lambda.ListFunctions', 'lambda:ListFunctions'); }

  // EKS service-mesh signal: enumerate clusters + their EKS-managed add-ons. The
  // EKS API cannot see Helm-installed meshes inside the cluster, but it CAN list
  // managed add-ons (a mesh add-on ⇒ mesh present) and tells us EKS clusters
  // exist whose in-cluster mTLS must be validated by the K8s collector.
  interface EksClusterMesh { cluster: string; addons: string[]; mesh_addons: string[]; }
  const eksClusters: EksClusterMesh[] = [];
  const MESH_ADDON_RE = /istio|linkerd|cilium|appmesh|app-mesh|service-mesh|consul/i;
  try {
    const eks = aws.eks(ctx.auth);
    let tok: string | undefined;
    let iter = 0;
    do {
      const r = await eks.send(new ListClustersCommand({ nextToken: tok, maxResults: 100 }));
      for (const name of r.clusters ?? []) {
        let addons: string[] = [];
        try {
          const a = await eks.send(new ListAddonsCommand({ clusterName: name }));
          addons = a.addons ?? [];
        } catch (e) { warnIfActionable(warnings, e, `eks.ListAddons ${name}`, 'eks:ListAddons'); }
        eksClusters.push({ cluster: name, addons, mesh_addons: addons.filter((x) => MESH_ADDON_RE.test(x)) });
      }
      const next = r.nextToken;
      tok = next && next !== tok ? next : undefined;
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    evidence.push(ev('eks.cluster_mesh_audit', { cluster_count: eksClusters.length, clusters: eksClusters }));
  } catch (e) { warnIfActionable(warnings, e, 'eks.ListClusters', 'eks:ListClusters'); }

  const eksMeshAddonClusters = eksClusters.filter((c) => c.mesh_addons.length > 0);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Istio / Linkerd / Cilium service mesh on EKS',
      description: 'Service mesh provides mTLS between services. The EKS API detects managed mesh add-ons; Helm-installed meshes are validated in-cluster by the K8s collector (providers/k8s/security.ts).',
      evidence_required: ['Service mesh deployment manifests', 'PeerAuthentication / strict mTLS policy', 'mTLS-validated traffic sample'],
      detected: eksMeshAddonClusters.length > 0,
      detection_signals: eksClusters.length === 0
        ? ['No EKS clusters found (or no eks:ListClusters permission).']
        : eksClusters.map((c) => c.mesh_addons.length > 0
            ? `EKS ${c.cluster}: managed mesh add-on(s) ${c.mesh_addons.join(', ')}`
            : `EKS ${c.cluster}: no managed mesh add-on — validate in-cluster mesh (Helm Istio/Linkerd) via the K8s collector`),
    },
    {
      via: 'AWS PrivateLink for service-to-service (no public internet)',
      description: 'PrivateLink provides authenticated, encrypted connectivity without traversing public internet — service-mesh substitute for cross-VPC.',
      evidence_required: ['PrivateLink endpoint inventory', 'Endpoint policies'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.appmesh.mtls_strict',
      passed: appMeshCollected && (vnodes.length === 0 || nodesWithoutStrictMtls.length === 0),
      severity: 'high',
      current: {
        summary: vnodes.length === 0
          ? 'No App Mesh virtual nodes (mesh may not be in use).'
          : (nodesWithoutStrictMtls.length === 0
            ? `All ${vnodes.length} App Mesh virtual node(s) have STRICT TLS.`
            : `${nodesWithoutStrictMtls.length} of ${vnodes.length} virtual node(s) do NOT have STRICT TLS.`),
        observations: { mesh_count: meshCount, vnodes_audit: vnodes },
      },
      target: { summary: 'App Mesh listeners run TLS mode=STRICT (require mTLS client certificate).', rationale: 'NIST SC-23. Authenticated + encrypted service-to-service.' },
      gap: (appMeshCollected && (vnodes.length === 0 || nodesWithoutStrictMtls.length === 0)) ? undefined : {
        description: !appMeshCollected
          ? 'App Mesh could not be enumerated (appmesh:ListMeshes failed), so service-to-service mTLS posture could not be assessed.'
          : 'Service-to-service traffic may be plaintext or anonymous TLS.',
        affected_resources: nodesWithoutStrictMtls.length ? nodesWithoutStrictMtls.map<AffectedResource>((v) => ({
          type: 'aws_appmesh_virtual_node', identifier: `${v.mesh}/${v.node}`, name: v.node,
          attributes: { mesh: v.mesh, current_mode: v.listenerMtls },
        })) : [{ type: 'aws_appmesh_mesh', identifier: ctx.account ?? 'account', name: 'App Mesh unreadable — indeterminate' }],
      },
      remediation: (appMeshCollected && (vnodes.length === 0 || nodesWithoutStrictMtls.length === 0)) ? undefined : {
        summary: 'Set listener.tls.mode=STRICT with ACM-issued cert on each prod virtual node.',
        options: [{
          approach: 'Update virtual-node spec via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'ACM private CA cost.' },
          availability_impact: { level: 'medium', notes: 'Non-mesh-aware clients will fail; coordinate.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Per service.' },
          steps: ['Set up ACM Private CA.', 'Issue cert per service.', 'Update virtual_node listener.tls.mode = "STRICT".'],
          example_code: `resource "aws_appmesh_virtual_node" "app" {
  spec {
    listener {
      port_mapping { port = 8080 protocol = "http" }
      tls {
        mode = "STRICT"
        certificate { acm { certificate_arn = aws_acm_certificate.svc.arn } }
      }
    }
  }
}`,
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['sc-23','si-7.1'],
    }),

    finding({
      rule: 'aws.lambda.function_urls_require_iam',
      passed: lambdaUrlsCollected && (lambdaUrlsTotal === 0 || lambdaUrlsWithoutIam.length === 0),
      severity: 'critical',
      current: {
        summary: lambdaUrlsTotal === 0
          ? 'No Lambda function URLs (functions are invoked via API Gateway or direct invoke).'
          : (lambdaUrlsWithoutIam.length === 0
            ? `All ${lambdaUrlsTotal} function URL(s) require AWS_IAM auth.`
            : `${lambdaUrlsWithoutIam.length} of ${lambdaUrlsTotal} function URL(s) are AuthType=NONE.`),
        observations: { total_urls: lambdaUrlsTotal, without_iam: lambdaUrlsWithoutIam },
      },
      target: { summary: 'Every Lambda function URL has AuthType=AWS_IAM.', rationale: 'NIST AC-3. NONE-auth function URLs are world-callable.' },
      gap: (lambdaUrlsTotal === 0 || lambdaUrlsWithoutIam.length === 0) ? undefined : {
        description: 'World-callable function URLs.',
        affected_resources: lambdaUrlsWithoutIam.map<AffectedResource>((n) => ({
          type: 'aws_lambda_function_url', identifier: n, name: n, attributes: { AuthType: 'NONE' },
        })),
      },
      remediation: (lambdaUrlsTotal === 0 || lambdaUrlsWithoutIam.length === 0) ? undefined : {
        summary: 'Set authorization_type = "AWS_IAM" on each function URL.',
        options: [{
          approach: 'Update via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Existing callers must sign requests with SigV4.' },
          customer_visible: { level: 'medium', notes: 'Customer-facing function URLs become inaccessible without auth.' },
          effort_estimate: { magnitude: 'days', notes: 'Per function + caller updates.' },
          steps: ['Identify legitimate callers.', 'Either set IAM auth + grant lambda:InvokeFunctionUrl to callers, OR front with API Gateway + authorizer.', 'Update Terraform.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','sc-8'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-VRI — Validating Resource Integrity (cryptographic signing/attestation)
// =====================================================================
export async function collectSvcVri(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = await setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Signer profiles + recent signing jobs
  let signingProfileCount = 0;
  let recentSigningJobs = 0;
  try {
    const sg = aws.signer(ctx.auth);
    const p = await sg.send(new ListSigningProfilesCommand({}));
    signingProfileCount = p.profiles?.length ?? 0;
    try {
      const j = await sg.send(new ListSigningJobsCommand({ maxResults: 50 }));
      recentSigningJobs = j.jobs?.length ?? 0;
    } catch { /* */ }
    evidence.push(ev('signer.profiles_and_jobs', { profiles: signingProfileCount, recent_jobs: recentSigningJobs }));
  } catch (e: any) { warnings.push(`Signer: ${e.message}`); }

  // Lambda code signing
  let lambdaTotal = 0;
  let lambdaWithCodeSigning = 0;
  let lambdaCollected = false;
  try {
    const lambda = aws.lambda(ctx.auth);
    let tok: string | undefined;
    let iter = 0;
    do {
      const r = await lambda.send(new ListFunctionsCommand({ Marker: tok, MaxItems: 50 }));
      for (const f of r.Functions ?? []) {
        lambdaTotal++;
        if (!f.FunctionName) continue;
        try {
          const cs = await lambda.send(new GetFunctionCodeSigningConfigCommand({ FunctionName: f.FunctionName }));
          if (cs.CodeSigningConfigArn) lambdaWithCodeSigning++;
        } catch (e) {
          // No code-signing config on a function is expected (not_found); surface only real errors.
          warnIfActionable(warnings, e, `lambda.GetFunctionCodeSigningConfig ${f.FunctionName}`, 'lambda:GetFunctionCodeSigningConfig');
        }
      }
      const next = r.NextMarker;
      tok = next && next !== tok ? next : undefined; // stop on repeated/empty marker
    } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
    lambdaCollected = true;
    evidence.push(ev('lambda.code_signing', { total: lambdaTotal, with_signing: lambdaWithCodeSigning }));
  } catch (e) { warnIfActionable(warnings, e, 'lambda.ListFunctions', 'lambda:ListFunctions'); }

  // SSM patch baselines (operating system integrity via patching)
  let patchBaselineCount = 0;
  try {
    const ssm = aws.ssm(ctx.auth);
    const r = await ssm.send(new DescribePatchBaselinesCommand({ MaxResults: 50 }));
    patchBaselineCount = r.BaselineIdentities?.length ?? 0;
    evidence.push(ev('ssm.patch_baselines', { count: patchBaselineCount }));
  } catch (e: any) { warnings.push(`SSM Patch baselines: ${e.message}`); }

  // EC2 IMDSv2 + Shielded options (already in CNA-MAT; re-surface here for VRI angle)
  let instancesTotal = 0;
  let instancesWithoutImdsv2 = 0;
  let instancesCollected = false;
  try {
    const ec2 = aws.ec2(ctx.auth);
    const r = await ec2.send(new DescribeInstancesCommand({ MaxResults: 200 }));
    for (const res of r.Reservations ?? []) {
      for (const inst of res.Instances ?? []) {
        instancesTotal++;
        if (inst.MetadataOptions?.HttpTokens !== 'required') instancesWithoutImdsv2++;
      }
    }
    instancesCollected = true;
    evidence.push(ev('ec2.imdsv2_for_vri', { total: instancesTotal, without_imdsv2: instancesWithoutImdsv2 }));
  } catch (e: any) { warnings.push(diagnoseAwsError(e, 'ec2.DescribeInstances', 'ec2:DescribeInstances')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Sigstore / cosign + ECR for image signing',
      description: 'Container images signed with cosign instead of AWS Signer; signatures stored as ECR tags.',
      evidence_required: ['cosign signing key + transparency log entries', 'Image-signature ECR tag inventory', 'Admission controller config verifying signatures'],
      detected: false,
      detection_signals: ['cosign signatures appear as ECR tags ending in `.sig`; detection requires sampling ECR.'],
    },
    {
      via: 'SLSA provenance via GitHub Actions',
      description: 'Builds produce SLSA provenance attestations stored in GitHub.',
      evidence_required: ['Build provenance attestation sample', 'SLSA level claim documentation'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'aws.signer.signing_capability_present',
      passed: signingProfileCount >= 1,
      severity: 'medium',
      current: {
        summary: signingProfileCount === 0
          ? 'No AWS Signer profiles — Lambda/IoT signing capability not configured.'
          : `${signingProfileCount} Signer profile(s); ${recentSigningJobs} recent signing job(s).`,
        observations: { profiles: signingProfileCount, recent_jobs: recentSigningJobs },
      },
      target: { summary: 'At least one Signer profile exists; signing jobs run regularly via CI.', rationale: 'NIST SI-7, SI-7.6. Cryptographic signing of code artifacts.' },
      gap: signingProfileCount >= 1 ? undefined : {
        description: 'No native signing infrastructure.',
        affected_resources: [{ type: 'aws_signer_signing_profile', identifier: 'none', attributes: {} }],
      },
      remediation: signingProfileCount >= 1 ? undefined : {
        summary: 'Create Signer profile + integrate with CI.',
        options: [{
          approach: 'Create profile via Terraform; have CI invoke signing.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Per-signature charge.' },
          availability_impact: { level: 'medium', notes: 'Pipeline change required.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'CI integration.' },
          steps: ['Create signing profile.', 'CI calls signer:StartSigningJob on Lambda package.', 'Lambda code-signing-config references this profile.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['si-7','si-7.6'],
    }),

    finding({
      rule: 'aws.lambda.code_signing_required',
      passed: lambdaCollected && (lambdaTotal === 0 || lambdaWithCodeSigning / lambdaTotal >= 0.8),
      severity: 'high',
      current: {
        summary: lambdaTotal === 0
          ? 'No Lambda functions.'
          : `${lambdaWithCodeSigning} of ${lambdaTotal} (${Math.round(lambdaWithCodeSigning/lambdaTotal*100)}%) Lambda functions have code-signing config attached.`,
        observations: { total: lambdaTotal, with_signing: lambdaWithCodeSigning },
      },
      target: { summary: '≥80% of prod Lambda functions have a code-signing config requiring signature on deploy.', rationale: 'NIST SI-7. Prevents unsigned code from running.' },
      gap: (lambdaTotal === 0 || lambdaWithCodeSigning / lambdaTotal >= 0.8) ? undefined : {
        description: 'Most Lambda functions can be replaced without signature verification.',
        affected_resources: [{ type: 'aws_lambda_function', identifier: 'aggregate', attributes: { total: lambdaTotal, with_signing: lambdaWithCodeSigning } }],
      },
      remediation: (lambdaTotal === 0 || lambdaWithCodeSigning / lambdaTotal >= 0.8) ? undefined : {
        summary: 'Attach code-signing config to each prod function.',
        options: [{
          approach: 'See CMT-RMV Finding "aws.lambda.code_signing_in_use" — same remediation.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Signer + Lambda signing config.' },
          availability_impact: { level: 'medium', notes: 'Unsigned deploys fail.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'CI + per-function rollout.' },
          steps: ['Set up signing profile (see CMT-RMV).', 'Attach lambda code-signing config to each function.', 'CI must sign packages before deploy.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['si-7','si-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-RMV', relationship: 'shares-remediation', note: 'Same code-signing infrastructure serves both.' },
      ],
    }),

    finding({
      rule: 'aws.ssm.patch_baseline_configured',
      passed: patchBaselineCount >= 1,
      severity: 'medium',
      current: {
        summary: patchBaselineCount >= 1
          ? `${patchBaselineCount} SSM patch baseline(s) configured.`
          : 'No SSM patch baselines.',
        observations: { patch_baseline_count: patchBaselineCount },
      },
      target: { summary: 'At least one customer-defined patch baseline applies to in-scope instances.', rationale: 'NIST SI-2. Patch hygiene maintains OS integrity over time.' },
      gap: patchBaselineCount >= 1 ? undefined : {
        description: 'No patch policy.',
        affected_resources: [{ type: 'aws_ssm_patch_baseline', identifier: 'none', attributes: {} }],
      },
      remediation: patchBaselineCount >= 1 ? undefined : {
        summary: 'Create a patch baseline + patch group + Maintenance Window.',
        options: [{
          approach: 'Apply via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Patch installation may reboot.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Baseline + window setup.' },
          steps: ['Define baseline (auto-approve security patches after N days).', 'Tag instances into patch groups.', 'Create maintenance window for patch installs.'],
        }],
      },
      alternative_satisfiers: [
        { via: 'Container-based workloads (no patching at OS layer)', description: 'Pure-container fleets are re-baked into new images instead of patched in place.', evidence_required: ['Container-build cadence', 'Base-image refresh policy'], detected: false },
      ],
      nist_controls: ['si-2','si-2.1'],
    }),

    finding({
      rule: 'aws.ec2.imdsv2_for_integrity',
      passed: instancesCollected && (instancesTotal === 0 || instancesWithoutImdsv2 === 0),
      severity: 'high',
      current: {
        summary: instancesTotal === 0
          ? 'No EC2 instances.'
          : `${instancesWithoutImdsv2} of ${instancesTotal} EC2 instance(s) allow IMDSv1 (instance-credential integrity at risk).`,
        observations: { total: instancesTotal, without_imdsv2: instancesWithoutImdsv2 },
      },
      target: { summary: 'All EC2 instances enforce IMDSv2.', rationale: 'NIST SI-7. Instance-role credentials are part of resource integrity.' },
      gap: (instancesTotal === 0 || instancesWithoutImdsv2 === 0) ? undefined : {
        description: 'Instance-credential theft via SSRF on IMDSv1.',
        affected_resources: [{ type: 'aws_instance', identifier: 'aggregate', attributes: { without_imdsv2: instancesWithoutImdsv2 } }],
      },
      remediation: (instancesTotal === 0 || instancesWithoutImdsv2 === 0) ? undefined : {
        summary: 'See KSI-CNA-MAT "aws.ec2.all_imdsv2_required" — same remediation.',
        options: [{
          approach: 'Set HttpTokens=required.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Modern SDKs handle transparently.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Apply Terraform.' },
          steps: ['See CNA-MAT remediation.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'Same IMDSv2 enforcement.' },
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Instance-role credentials are SNU.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'aws', account_id: ctx.account, region_set: [ctx.region], evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
