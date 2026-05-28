/**
 * GCP data-domain collectors.
 *   - KSI-SVC-RUD — Removing Unwanted Data
 *   - KSI-SVC-VCM — Validating Communications (service-to-service)
 *   - KSI-SVC-VRI — Validating Resource Integrity (BinAuthz attestations, Shielded VM)
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

// =====================================================================
// KSI-SVC-RUD — Removing Unwanted Data
// =====================================================================
export async function collectSvcRud(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud Storage lifecycle + retention
  interface BucketLifecycle { name: string; hasLifecycleRule: boolean; retentionPolicy?: any; versioning: boolean; }
  const buckets: BucketLifecycle[] = [];
  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const r = await storage.buckets.list({ project: ctx.project });
    for (const b of r.data.items ?? []) {
      buckets.push({
        name: b.name,
        hasLifecycleRule: (b.lifecycle?.rule ?? []).length > 0,
        retentionPolicy: b.retentionPolicy,
        versioning: !!b.versioning?.enabled,
      });
    }
    evidence.push(ev('storage.bucket_lifecycle', buckets));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  const bucketsWithoutLifecycle = buckets.filter((b) => !b.hasLifecycleRule && !b.retentionPolicy);

  // Cloud SQL backup retention
  interface SqlRetention { name: string; backupConfig?: any; }
  const sqlInstances: SqlRetention[] = [];
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      sqlInstances.push({ name: i.name, backupConfig: i.settings?.backupConfiguration });
    }
    evidence.push(ev('sqladmin.backup_retention', sqlInstances));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  // BigQuery table default expiration
  let datasetsWithoutDefaultExpiration: string[] = [];
  let datasetCount = 0;
  try {
    const bq = await gcpAuth.googleClient<any>('bigquery', 'v2');
    const r = await bq.datasets.list({ projectId: ctx.project });
    for (const d of r.data.datasets ?? []) {
      datasetCount++;
      // Need to GET each to see defaultTableExpirationMs — sample first 10
      if (datasetCount <= 10) {
        try {
          const ds = await bq.datasets.get({ projectId: ctx.project, datasetId: d.datasetReference?.datasetId });
          if (!ds.data.defaultTableExpirationMs) datasetsWithoutDefaultExpiration.push(d.datasetReference?.datasetId ?? '');
        } catch { /* */ }
      }
    }
    evidence.push(ev('bigquery.dataset_retention', { dataset_count: datasetCount, sampled: Math.min(10, datasetCount), without_default_expiration: datasetsWithoutDefaultExpiration }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'bigquery.datasets.list/get', 'bigquery.datasets.get (roles/bigquery.metadataViewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Customer-data-request workflow tool (Drata DSR, OneTrust, custom Cloud Function)',
      description: 'Ad-hoc deletion via dedicated workflow; cloud-side lifecycle handles only proactive retention.',
      evidence_required: ['DSR runbook URL', 'Sample request with execution log', 'Auditable deletion trail'],
      detected: false,
      detection_signals: [],
    },
  ];

  // Demonstrate the deletion mechanism with real evidence: query Cloud Audit Logs
  // (Admin Activity) for recent delete events. Read-only: logging entries.list.
  const DELETION_METHODS = [
    'storage.objects.delete',
    'storage.buckets.delete',
    'cloudsql.backupRuns.delete',
    'cloudkms.cryptoKeyVersions.destroy',
    'bigquery.tables.delete',
    'bigquery.datasets.delete',
    'compute.disks.delete',
    'compute.snapshots.delete',
  ];
  const WINDOW_DAYS = 90;
  let deletionEvents = 0;
  const deletionSamples: Array<{ method: string; resource: string | null; timestamp: string | null }> = [];
  const deletionMethodCounts: Record<string, number> = {};
  let deletionQueryOk = false;
  try {
    const logging = await gcpAuth.googleClient<any>('logging', 'v2');
    const since = new Date(Date.now() - WINDOW_DAYS * 86400_000).toISOString();
    const methodFilter = DELETION_METHODS.map((m) => `protoPayload.methodName="${m}"`).join(' OR ');
    const filter = `logName:"cloudaudit.googleapis.com" AND (${methodFilter}) AND timestamp>="${since}"`;
    const r = await logging.entries.list({
      requestBody: { resourceNames: [`projects/${ctx.project}`], filter, orderBy: 'timestamp desc', pageSize: 100 },
    });
    deletionQueryOk = true;
    for (const entry of r.data.entries ?? []) {
      const method = entry.protoPayload?.methodName ?? 'unknown';
      deletionEvents++;
      deletionMethodCounts[method] = (deletionMethodCounts[method] ?? 0) + 1;
      if (deletionSamples.length < 10) {
        deletionSamples.push({
          method,
          resource: entry.protoPayload?.resourceName ?? entry.resource?.type ?? null,
          timestamp: entry.timestamp ?? null,
        });
      }
    }
    evidence.push(ev('logging.deletion_events', { window_days: WINDOW_DAYS, total: deletionEvents, by_method: deletionMethodCounts, samples: deletionSamples }));
  } catch (e) {
    warnings.push(diagnoseGcpError(e, 'logging.entries.list (deletion events)', 'logging.entries.list (roles/logging.viewer or roles/logging.privateLogViewer)'));
  }

  const findings = [
    finding({
      rule: 'gcp.storage.buckets_have_lifecycle_or_retention',
      passed: bucketsWithoutLifecycle.length === 0,
      severity: 'medium',
      current: {
        summary: bucketsWithoutLifecycle.length === 0
          ? `All ${buckets.length} bucket(s) have lifecycle rules or retention policies.`
          : `${bucketsWithoutLifecycle.length} of ${buckets.length} bucket(s) lack both lifecycle and retention.`,
        observations: { without_lifecycle_or_retention: bucketsWithoutLifecycle.map((b) => b.name) },
      },
      target: { summary: 'Every prod bucket has lifecycle.rule (auto-deletion) OR retentionPolicy (locked retention), matched to data class.', rationale: 'NIST MP-6, SI-12.' },
      gap: bucketsWithoutLifecycle.length === 0 ? undefined : {
        description: 'Indefinite-retention without intent.',
        affected_resources: bucketsWithoutLifecycle.map<AffectedResource>((b) => ({
          type: 'google_storage_bucket', identifier: b.name, name: b.name, attributes: {},
        })),
      },
      remediation: bucketsWithoutLifecycle.length === 0 ? undefined : {
        summary: 'Apply lifecycle rules matching retention requirements.',
        options: [{
          approach: 'Add lifecycle block via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free; lower storage cost.' },
          availability_impact: { level: 'medium', notes: 'Audit retention needs first.' },
          customer_visible: { level: 'medium', notes: 'For federal customer data, lifecycle must match contractual terms.' },
          effort_estimate: { magnitude: 'days', notes: 'Per bucket.' },
          steps: ['Document retention requirement per bucket.', 'Apply lifecycle rule.', 'Test on subset.'],
          example_code: `resource "google_storage_bucket" "data" {
  name = "your-data-bucket"
  lifecycle_rule {
    condition { age = 365 }
    action    { type = "Delete" }
  }
  versioning { enabled = true }
}`,
        }],
      },
      alternative_satisfiers: [
        { via: 'Bucket has retentionPolicy with locked retention matching contractual obligation', description: 'Indefinite-retention is intentional under retentionPolicy.', evidence_required: ['retentionPolicy object', 'Contractual retention term'], detected: false },
      ],
      nist_controls: ['mp-6','si-12'],
    }),

    finding({
      rule: 'gcp.bigquery.dataset_default_expiration',
      passed: datasetsWithoutDefaultExpiration.length === 0,
      severity: 'low',
      current: {
        summary: datasetsWithoutDefaultExpiration.length === 0
          ? `Sampled datasets have default table expiration.`
          : `${datasetsWithoutDefaultExpiration.length} dataset(s) lack defaultTableExpirationMs.`,
        observations: { sampled_without_expiration: datasetsWithoutDefaultExpiration },
      },
      target: { summary: 'Datasets in scope have a defaultTableExpirationMs OR per-table expiration set.', rationale: 'NIST SI-12.' },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['si-12'],
      note: 'Sampled first 10 datasets — extend collection if more visibility needed.',
    }),

    finding({
      rule: 'gcp.deletion_mechanism_demonstrated',
      // Informational: a found deletion event proves the mechanism works; finding
      // none isn't a failure (may simply be a quiet window), so this never fails.
      passed: true,
      severity: 'info',
      current: {
        summary: !deletionQueryOk
          ? `Could not query Cloud Audit Logs for deletion events (see warnings); supply evidence via a SIEM saved query.`
          : (deletionEvents > 0
            ? `Deletion mechanism demonstrated: ${deletionEvents} delete event(s) in the last ${WINDOW_DAYS} days across ${Object.keys(deletionMethodCounts).length} method(s) (${Object.entries(deletionMethodCounts).map(([m, n]) => `${m}=${n}`).join(', ')}).`
            : `No delete events in the last ${WINDOW_DAYS} days (audit logs reachable). Mechanism is in place; no recent deletions to show.`),
        observations: {
          window_days: WINDOW_DAYS,
          query_succeeded: deletionQueryOk,
          total_deletion_events: deletionEvents,
          by_method: deletionMethodCounts,
          samples: deletionSamples,
          methods_checked: DELETION_METHODS,
        },
      },
      target: { summary: 'Past deletion events are visible in audit logs (Admin Activity), demonstrating the data-removal mechanism.', rationale: 'NIST MP-6.' },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['mp-6'],
      note: deletionQueryOk ? undefined : 'Audit-log query failed (permission/availability); fall back to a SIEM saved query for production evidence.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-VCM — Validating Communications
// =====================================================================
export async function collectSvcVcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud Service Mesh detection (via gkehub feature)
  let csmEnabled = false;
  let clustersWithCsm: string[] = [];
  try {
    const gkehub = await gcpAuth.googleClient<any>('gkehub', 'v1');
    const r = await gkehub.projects.locations.features.list({ parent: `projects/${ctx.project}/locations/global` });
    for (const f of r.data.resources ?? []) {
      if (/servicemesh/.test(f.name ?? '')) {
        csmEnabled = true;
        for (const [m, _] of Object.entries(f.membershipStates ?? {})) clustersWithCsm.push(m);
      }
    }
    evidence.push(ev('gkehub.servicemesh', { enabled: csmEnabled, clusters: clustersWithCsm }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'gkehub.projects.locations.features.list', 'gkehub.features.list (roles/gkehub.viewer)')); }

  // IAP web backend services — count of services protected
  let iapBackendServices = 0;
  try {
    const iap = await gcpAuth.googleClient<any>('iap', 'v1');
    const r = await iap.projects.brands.list({ parent: `projects/${ctx.project}` });
    iapBackendServices = (r.data.brands ?? []).length;
    evidence.push(ev('iap.brand_count', { count: iapBackendServices }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'iap.projects.brands.list', 'iap.web.getIamPolicy (roles/iap.admin or roles/iap.settingsAdmin)')); }

  // Cloud Run services with internal-only ingress
  let cloudRunInternal: string[] = [];
  let cloudRunTotal = 0;
  try {
    const run = await gcpAuth.googleClient<any>('run', 'v1');
    const r = await run.namespaces.services.list({ parent: `namespaces/${ctx.project}` });
    for (const s of r.data.items ?? []) {
      cloudRunTotal++;
      const ing = s.metadata?.annotations?.['run.googleapis.com/ingress'];
      if (ing === 'internal' || ing === 'internal-and-cloud-load-balancing') {
        cloudRunInternal.push(s.metadata?.name ?? '?');
      }
    }
    evidence.push(ev('run.ingress_audit', { total: cloudRunTotal, internal_or_lb_only: cloudRunInternal.length }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'run.services.list', 'run.services.list (roles/run.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Istio / Linkerd / Cilium service mesh on GKE',
      description: 'Service mesh provides mTLS. Detection requires kubectl access.',
      evidence_required: ['Mesh deployment manifests', 'PeerAuthentication strict mode', 'Cert rotation logs'],
      detected: csmEnabled,
      detection_signals: csmEnabled ? clustersWithCsm.map((c) => `Cloud Service Mesh on ${c}`) : [],
    },
    {
      via: 'Private Service Connect',
      description: 'PSC provides private service-to-service connectivity within GCP.',
      evidence_required: ['PSC endpoint inventory', 'Service attachment + consumer config'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.service_mesh.enabled_for_mtls',
      passed: csmEnabled,
      severity: 'high',
      current: {
        summary: csmEnabled
          ? `Cloud Service Mesh enabled across ${clustersWithCsm.length} cluster(s).`
          : 'Cloud Service Mesh not detected — service-to-service mTLS likely unenforced.',
        observations: { csm_enabled: csmEnabled, clusters: clustersWithCsm },
      },
      target: { summary: 'Cloud Service Mesh (or equivalent Istio/Linkerd/Cilium) enabled with strict mTLS on prod clusters.', rationale: 'NIST SC-23. Authenticated + encrypted service-to-service.' },
      gap: csmEnabled ? undefined : {
        description: 'No native service-mesh enforcement of mTLS.',
        affected_resources: [{ type: 'google_gke_hub_feature', identifier: 'servicemesh', attributes: { enabled: false } }],
      },
      remediation: csmEnabled ? undefined : {
        summary: 'Enable Cloud Service Mesh fleet feature on prod GKE clusters.',
        options: [{
          approach: 'Enable CSM via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'medium', notes: 'Anthos Service Mesh license; per-cluster cost.' },
          availability_impact: { level: 'medium', notes: 'Sidecar injection requires pod restart.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Cluster setup + per-namespace migration.' },
          steps: ['Enable servicemesh feature on the fleet.', 'Register prod clusters as fleet memberships.', 'Apply strict PeerAuthentication per namespace.'],
          example_code: `resource "google_gke_hub_feature" "servicemesh" {
  name     = "servicemesh"
  location = "global"
}`,
          references: [{ title: 'Cloud Service Mesh', url: 'https://cloud.google.com/service-mesh/docs' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['sc-23','si-7.1'],
    }),

    finding({
      rule: 'gcp.cloud_run.internal_ingress_for_internal_services',
      passed: cloudRunTotal === 0 || cloudRunInternal.length === cloudRunTotal,
      severity: 'medium',
      current: {
        summary: cloudRunTotal === 0
          ? 'No Cloud Run services in this project.'
          : `${cloudRunInternal.length} of ${cloudRunTotal} Cloud Run service(s) restrict ingress to internal/LB-only.`,
        observations: { total: cloudRunTotal, internal_or_lb_only: cloudRunInternal.length },
      },
      target: { summary: 'Internal Cloud Run services use ingress=internal or internal-and-cloud-load-balancing; only customer-facing services accept public ingress (and those go through Cloud Armor + IAP).', rationale: 'NIST SC-7, AC-3.' },
      gap: (cloudRunTotal === 0 || cloudRunInternal.length === cloudRunTotal) ? undefined : {
        description: 'Some internal services may be publicly reachable.',
        affected_resources: [],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','ac-3'],
      note: 'Cannot programmatically distinguish "internal-only" from "customer-facing" here — surface for human review.',
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-VRI — Validating Resource Integrity
// =====================================================================
export async function collectSvcVri(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Binary Authorization attestors + policy enforcement
  let attestorCount = 0;
  let policyMode = 'unknown';
  try {
    const ba = await gcpAuth.googleClient<any>('binaryauthorization', 'v1');
    const p = await ba.projects.getPolicy({ name: `projects/${ctx.project}/policy` });
    policyMode = p.data.defaultAdmissionRule?.evaluationMode ?? 'NOT_SET';
    const at = await ba.projects.attestors.list({ parent: `projects/${ctx.project}` });
    attestorCount = (at.data.attestors ?? []).length;
    evidence.push(ev('binaryauthorization.attestors_and_policy', { attestor_count: attestorCount, policy_mode: policyMode, policy: p.data }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'binaryauthorization.projects.getPolicy', 'binaryauthorization.policy.get (roles/binaryauthorization.policyViewer)')); }

  // Container Analysis ATTESTATION occurrences (proof attestations are being created)
  let attestationOccurrences = 0;
  try {
    const ca = await gcpAuth.googleClient<any>('containeranalysis', 'v1');
    const r = await ca.projects.occurrences.list({ parent: `projects/${ctx.project}`, filter: 'kind="ATTESTATION"', pageSize: 100 });
    attestationOccurrences = (r.data.occurrences ?? []).length;
    evidence.push(ev('containeranalysis.attestation_count', attestationOccurrences));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'containeranalysis.projects.occurrences.list', 'containeranalysis.occurrences.list (roles/containeranalysis.occurrences.viewer)')); }

  // GKE shieldedNodes + workloadIdentity (already partly in network.ts, surface for VRI)
  let clustersWithShieldedNodes: string[] = [];
  let clustersTotal = 0;
  try {
    const container = await gcpAuth.googleClient<any>('container', 'v1');
    const r = await container.projects.locations.clusters.list({ parent: `projects/${ctx.project}/locations/-` });
    for (const c2 of r.data.clusters ?? []) {
      clustersTotal++;
      if (c2.shieldedNodes?.enabled) clustersWithShieldedNodes.push(c2.name);
    }
    evidence.push(ev('container.shielded_nodes', { total: clustersTotal, with_shielded: clustersWithShieldedNodes }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'container.clusters.list', 'container.clusters.list (roles/container.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Sigstore / cosign for OCI image signing',
      description: 'Container images signed via cosign + Rekor transparency log; verified at admission via cosigned policy controller.',
      evidence_required: ['cosign signing key', 'Rekor log entries', 'Admission webhook config'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'SLSA provenance via Cloud Build (or external CI)',
      description: 'Builds produce SLSA provenance attestations.',
      evidence_required: ['SLSA level claim doc', 'Sample provenance attestation'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.binaryauthorization.attestors_present_and_enforced',
      passed: attestorCount >= 1 && (policyMode === 'REQUIRE_ATTESTATION' || policyMode === 'ALWAYS_DENY'),
      severity: 'high',
      current: {
        summary: `BinAuthz: policyMode=${policyMode}, attestors=${attestorCount}, attestation_occurrences=${attestationOccurrences}.`,
        observations: { policy_mode: policyMode, attestor_count: attestorCount, attestation_occurrences: attestationOccurrences },
      },
      target: { summary: 'Binary Authorization policy mode is REQUIRE_ATTESTATION with ≥1 attestor; attestations are being created.', rationale: 'NIST SI-7. Resource-integrity validation via signing infrastructure.' },
      gap: (attestorCount >= 1 && (policyMode === 'REQUIRE_ATTESTATION' || policyMode === 'ALWAYS_DENY')) ? undefined : {
        description: 'No attestation-enforced deployment chain.',
        affected_resources: [{ type: 'google_binary_authorization_policy', identifier: ctx.project, attributes: { policy_mode: policyMode, attestor_count: attestorCount } }],
      },
      remediation: (attestorCount >= 1 && (policyMode === 'REQUIRE_ATTESTATION' || policyMode === 'ALWAYS_DENY')) ? undefined : {
        summary: 'See KSI-CMT-RMV remediation for full setup — same infrastructure satisfies both.',
        options: [{
          approach: 'BinAuthz + attestor + signing key via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'KMS signing key cost.' },
          availability_impact: { level: 'medium', notes: 'Unattested images blocked.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Pipeline integration.' },
          steps: ['See CMT-RMV remediation.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['si-7','si-7.1','si-7.6'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-RMV', relationship: 'shares-remediation', note: 'Same BinAuthz infrastructure.' },
        { ksi_id: 'KSI-CMT-VTD', relationship: 'precedes', note: 'Attestation creation is the VTD gate output.' },
      ],
    }),

    finding({
      rule: 'gcp.gke.shielded_nodes_enabled',
      passed: clustersTotal === 0 || clustersWithShieldedNodes.length === clustersTotal,
      severity: 'high',
      current: {
        summary: clustersTotal === 0
          ? 'No GKE clusters.'
          : `${clustersWithShieldedNodes.length} of ${clustersTotal} GKE cluster(s) have Shielded Nodes enabled.`,
        observations: { total: clustersTotal, with_shielded: clustersWithShieldedNodes },
      },
      target: { summary: 'All prod GKE clusters have shieldedNodes.enabled=true.', rationale: 'NIST SI-7. Hardware-rooted boot integrity for cluster nodes.' },
      gap: (clustersTotal === 0 || clustersWithShieldedNodes.length === clustersTotal) ? undefined : {
        description: 'Nodes without Shielded VM lack boot-integrity attestation.',
        affected_resources: [{ type: 'google_container_cluster', identifier: 'aggregate', attributes: { without_shielded_nodes: clustersTotal - clustersWithShieldedNodes.length } }],
      },
      remediation: (clustersTotal === 0 || clustersWithShieldedNodes.length === clustersTotal) ? undefined : {
        summary: 'Enable Shielded Nodes via Terraform.',
        options: [{
          approach: 'Set shielded_nodes.enabled via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Existing node pools must be recreated to gain shielded boot.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per cluster; node-pool replacement.' },
          steps: ['Set shielded_nodes.enabled=true.', 'Recreate node pools or wait for next upgrade.'],
          example_code: `resource "google_container_cluster" "this" {
  shielded_nodes { enabled = true }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-MAT', relationship: 'shares-remediation', note: 'Shielded VM also serves attack-surface reduction.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
