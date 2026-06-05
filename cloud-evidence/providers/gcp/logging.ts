/**
 * GCP logging-domain collectors.
 * Covers 5 MLA KSIs + CMT-LMC, mirroring providers/aws/logging.ts.
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

// ---- Shared logging inventory ----
interface LogInventory {
  sinks: any[];
  logBuckets: any[];
  auditConfigs: any[];
  dataAccessLoggingForServices: Set<string>;
}

async function fetchLogInventory(ctx: Ctx): Promise<{ inv: LogInventory; warnings: string[]; evidence: RawEvidence[] }> {
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const inv: LogInventory = { sinks: [], logBuckets: [], auditConfigs: [], dataAccessLoggingForServices: new Set() };

  try {
    const logging = await gcpAuth.googleClient<any>('logging', 'v2');
    const r = await logging.projects.sinks.list({ parent: `projects/${ctx.project}`, pageSize: 50 });
    inv.sinks = r.data.sinks ?? [];
    evidence.push(ev('logging.projects.sinks.list', inv.sinks.map((s: any) => ({ name: s.name, destination: s.destination, filter: s.filter?.slice(0, 200) }))));

    // Log buckets — both project-local and per-location
    const locations = ['global'];
    for (const loc of locations) {
      try {
        const b = await logging.projects.locations.buckets.list({ parent: `projects/${ctx.project}/locations/${loc}` });
        inv.logBuckets.push(...(b.data.buckets ?? []));
      } catch { /* ignore */ }
    }
    evidence.push(ev('logging.projects.locations.buckets.list', inv.logBuckets.map((b: any) => ({
      name: b.name, retentionDays: b.retentionDays, locked: b.locked, cmekKey: b.cmekSettings?.kmsKeyName,
    }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'logging.projects.sinks.list/buckets.list', 'logging.sinks.list (roles/logging.viewer)')); }

  // Data Access audit configs
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({
      resource: `projects/${ctx.project}`,
      requestBody: { options: { requestedPolicyVersion: 3 } },
    });
    inv.auditConfigs = r.data.auditConfigs ?? [];
    for (const ac of inv.auditConfigs) {
      const types = (ac.auditLogConfigs ?? []).map((l: any) => l.logType);
      if (types.includes('DATA_READ') && types.includes('DATA_WRITE')) {
        inv.dataAccessLoggingForServices.add(ac.service);
      }
    }
    evidence.push(ev('cloudresourcemanager.audit_configs', { services_with_data_logging: Array.from(inv.dataAccessLoggingForServices), configs: inv.auditConfigs }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy', 'resourcemanager.projects.getIamPolicy (roles/resourcemanager.projectIamAdmin or roles/viewer)')); }

  return { inv, warnings, evidence };
}

// =====================================================================
// KSI-CMT-LMC — Logging Changes (GCP)
// =====================================================================
export async function collectCmtLmc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchLogInventory(ctx);

  const requiredLockedBuckets = inv.logBuckets.filter((b: any) => /_Required/.test(b.name));
  const requiredLocked = requiredLockedBuckets.filter((b: any) => b.locked === true && (b.retentionDays ?? 0) >= 400);
  const bucketsWithCmek = inv.logBuckets.filter((b: any) => b.cmekSettings?.kmsKeyName);

  // Org-level audit sink check: at least one sink should route Admin Activity audit logs to a tamper-resistant destination
  const adminActivitySinks = inv.sinks.filter((s: any) => /logName.*cloudaudit\.googleapis\.com.*activity/i.test(s.filter ?? ''));

  const findings = [
    finding({
      rule: 'gcp.audit.required_bucket_locked_with_retention',
      passed: requiredLocked.length >= 1,
      severity: 'critical',
      current: {
        summary: requiredLocked.length >= 1
          ? `_Required log bucket(s) are locked with ≥400-day retention.`
          : `_Required log buckets found: ${requiredLockedBuckets.length}; locked with ≥400-day retention: ${requiredLocked.length}.`,
        observations: { all_log_buckets: inv.logBuckets.map((b: any) => ({ name: b.name, locked: b.locked, retentionDays: b.retentionDays })) },
      },
      target: { summary: 'The `_Required` log bucket has `locked=true` and retention ≥ 400 days, with CMEK encryption.', rationale: 'NIST AU-9, AU-11. Tamper-resistant audit-log storage with sufficient retention for FedRAMP audit cycles.' },
      gap: requiredLocked.length >= 1 ? undefined : {
        description: 'Without a locked _Required bucket, audit logs can be modified or deleted before audit.',
        affected_resources: requiredLockedBuckets.map<AffectedResource>((b: any) => ({
          type: 'google_logging_project_bucket_config', identifier: b.name, name: b.name, attributes: { locked: b.locked, retentionDays: b.retentionDays },
        })),
      },
      remediation: requiredLocked.length >= 1 ? undefined : {
        summary: 'Configure `_Required` log bucket with locked retention via Terraform.',
        options: [{
          approach: 'Update _Required bucket retention + lock via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Log Bucket storage charges per GB over time.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: [
            'Update `_Required` bucket retention to ≥ 400 days.',
            'Set `locked = true` (irreversible — once locked, retention cannot be reduced).',
            'Configure CMEK via cmekSettings.',
          ],
          example_code: `resource "google_logging_project_bucket_config" "required" {
  project        = var.project_id
  location       = "global"
  retention_days = 400
  locked         = true
  bucket_id      = "_Required"
}
resource "google_logging_project_cmek_settings" "this" {
  project    = var.project_id
  kms_key_name = google_kms_crypto_key.logs.id
}`,
          references: [{ title: 'Locked log retention', url: 'https://cloud.google.com/logging/docs/buckets#lock-bucket' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-9','au-10','au-11'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-ALA', relationship: 'shares-remediation', note: 'Log bucket IAM + CMEK are ALA evidence.' },
      ],
    }),

    finding({
      rule: 'gcp.audit.cmek_on_log_buckets',
      passed: bucketsWithCmek.length === inv.logBuckets.length && inv.logBuckets.length > 0,
      severity: 'high',
      current: {
        summary: inv.logBuckets.length === 0
          ? 'No log buckets found.'
          : `${bucketsWithCmek.length} of ${inv.logBuckets.length} log bucket(s) have CMEK configured.`,
        observations: { buckets_without_cmek: inv.logBuckets.filter((b: any) => !b.cmekSettings?.kmsKeyName).map((b: any) => b.name) },
      },
      target: { summary: 'Every in-scope log bucket has CMEK encryption.', rationale: 'NIST SC-13. Encrypt audit logs with org-controlled keys.' },
      gap: (bucketsWithCmek.length === inv.logBuckets.length && inv.logBuckets.length > 0) ? undefined : {
        description: 'Log buckets without CMEK use Google-managed encryption keys.',
        affected_resources: inv.logBuckets.filter((b: any) => !b.cmekSettings?.kmsKeyName).map<AffectedResource>((b: any) => ({
          type: 'google_logging_project_bucket_config', identifier: b.name, name: b.name, attributes: {},
        })),
      },
      remediation: (bucketsWithCmek.length === inv.logBuckets.length && inv.logBuckets.length > 0) ? undefined : {
        summary: 'Set cmekSettings on each log bucket.',
        options: [{
          approach: 'Apply cmekSettings via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'KMS usage.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Create CMEK key.', 'Grant cloud-logs service agent kms:cryptoKeyEncrypterDecrypter.', 'Set bucket cmekSettings.kmsKeyName.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-13'],
    }),

    finding({
      rule: 'gcp.audit.admin_activity_sink_present',
      passed: adminActivitySinks.length >= 1,
      severity: 'high',
      current: {
        summary: adminActivitySinks.length >= 1
          ? `${adminActivitySinks.length} sink(s) route Admin Activity audit logs to a long-term destination.`
          : 'No sink filters specifically capture Admin Activity audit logs — change events flow only to default 30-day _Required bucket.',
        observations: { sinks: inv.sinks.map((s: any) => ({ name: s.name, destination: s.destination, filter_preview: (s.filter ?? '').slice(0, 100) })) },
      },
      target: { summary: 'At least one sink routes `logName:cloudaudit.googleapis.com/activity` to a long-term destination (BigQuery, Pub/Sub, or a locked log bucket).', rationale: 'NIST AU-2, AU-11. Admin Activity logs are the change-event source; default retention is only 30 days.' },
      gap: adminActivitySinks.length >= 1 ? undefined : {
        description: 'Change-event retention is limited to 30 days unless explicitly sinked.',
        affected_resources: [{ type: 'google_logging_project_sink', identifier: 'no-admin-activity-sink', attributes: {} }],
      },
      remediation: adminActivitySinks.length >= 1 ? undefined : {
        summary: 'Create a sink filtering cloudaudit activity logs to a long-term destination.',
        options: [{
          approach: 'Sink → BigQuery dataset for long-term querying.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'BigQuery storage + query costs.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Create BigQuery dataset with retention.', 'Create logging sink with filter.', 'Grant sink writer the dataset.Owner role.'],
          example_code: `resource "google_logging_project_sink" "audit_to_bq" {
  name        = "audit-to-bq"
  destination = "bigquery.googleapis.com/projects/$\${var.project_id}/datasets/audit_logs"
  filter      = "logName:cloudaudit.googleapis.com%2Factivity"
  unique_writer_identity = true
}`,
          references: [{ title: 'Cloud Logging sinks', url: 'https://cloud.google.com/logging/docs/export/configure_export_v2' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','au-11'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-ALA — Authorizing Log Access (GCP)
// =====================================================================
export async function collectMlaAla(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchLogInventory(ctx);

  // Inspect IAM on log buckets
  interface BucketAccess { bucket: string; allUsers: boolean; allAuthenticatedUsers: boolean; cmek: string | null; }
  const accessAudits: BucketAccess[] = [];
  try {
    const logging = await gcpAuth.googleClient<any>('logging', 'v2');
    for (const b of inv.logBuckets) {
      try {
        // Log buckets use the Logging API for IAM
        const p = await logging.projects.locations.buckets.getIamPolicy?.({ resource: b.name }) ?? null;
        const policy = p?.data ?? {};
        const members = (policy.bindings ?? []).flatMap((bd: any) => bd.members ?? []);
        accessAudits.push({
          bucket: b.name,
          allUsers: members.includes('allUsers'),
          allAuthenticatedUsers: members.includes('allAuthenticatedUsers'),
          cmek: b.cmekSettings?.kmsKeyName ?? null,
        });
      } catch (e) {
        warnings.push(diagnoseGcpError(e, `logging.projects.locations.buckets.getIamPolicy (${b.name})`, 'logging.buckets.getIamPolicy (roles/logging.viewer)'));
      }
    }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'logging.projects.locations.buckets.getIamPolicy', 'logging.buckets.getIamPolicy (roles/logging.viewer)')); }
  evidence.push(ev('logging.bucket_iam_audit', accessAudits));

  // BigQuery datasets receiving audit log sinks — check their IAM
  const bqSinks = inv.sinks.filter((s: any) => /^bigquery\.googleapis\.com/.test(s.destination ?? ''));
  const bqOpenAudits: string[] = [];
  try {
    const bq = await gcpAuth.googleClient<any>('bigquery', 'v2');
    for (const sink of bqSinks) {
      const m = sink.destination.match(/datasets\/([^/]+)/);
      if (!m) continue;
      const datasetId = m[1];
      try {
        const ds = await bq.datasets.get({ projectId: ctx.project, datasetId });
        for (const a of ds.data.access ?? []) {
          if (a.specialGroup === 'allAuthenticatedUsers' || a.userByEmail === 'allUsers') {
            bqOpenAudits.push(`${datasetId}:${a.role}:${a.specialGroup ?? a.userByEmail}`);
          }
        }
      } catch { /* ignore */ }
    }
    evidence.push(ev('bigquery.audit_dataset_access', { dataset_count: bqSinks.length, open_access: bqOpenAudits }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'bigquery.datasets.get', 'bigquery.datasets.get (roles/bigquery.metadataViewer)')); }

  const openBuckets = accessAudits.filter((a) => a.allUsers || a.allAuthenticatedUsers).map((a) => a.bucket);

  const findings = [
    finding({
      rule: 'gcp.audit.log_buckets_no_public_iam',
      passed: openBuckets.length === 0,
      severity: 'critical',
      current: {
        summary: openBuckets.length === 0
          ? `All ${accessAudits.length} log bucket(s) have private IAM (no allUsers / allAuthenticatedUsers).`
          : `${openBuckets.length} log bucket(s) have public IAM bindings.`,
        observations: { audits: accessAudits, open_buckets: openBuckets },
      },
      target: { summary: 'Log bucket IAM lists only named security/audit principals; no allUsers / allAuthenticatedUsers.', rationale: 'NIST AC-3, SI-11.' },
      gap: openBuckets.length === 0 ? undefined : {
        description: 'Public IAM exposes audit log content.',
        affected_resources: openBuckets.map<AffectedResource>((b) => ({ type: 'google_logging_project_bucket_config', identifier: b, name: b, attributes: {} })),
      },
      remediation: openBuckets.length === 0 ? undefined : {
        summary: 'Remove public bindings; grant only the named auditor principals.',
        options: [{
          approach: 'Replace open bindings via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Anyone using the open binding loses access. Migrate first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per bucket.' },
          steps: ['Identify legitimate consumers.', 'Grant via named groups.', 'Remove allUsers/allAuthenticatedUsers.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','si-11'],
    }),

    finding({
      rule: 'gcp.audit.bigquery_audit_datasets_private',
      passed: bqOpenAudits.length === 0,
      severity: 'high',
      current: {
        summary: bqOpenAudits.length === 0
          ? `All ${bqSinks.length} BigQuery audit dataset(s) have private IAM.`
          : `${bqOpenAudits.length} BigQuery audit dataset binding(s) are publicly accessible.`,
        observations: { open_dataset_bindings: bqOpenAudits },
      },
      target: { summary: 'BigQuery datasets receiving audit-log sinks have no public bindings.', rationale: 'NIST AC-3, SI-11.' },
      gap: bqOpenAudits.length === 0 ? undefined : {
        description: 'Public BQ binding exposes audit query results.',
        affected_resources: bqOpenAudits.map<AffectedResource>((d) => ({ type: 'google_bigquery_dataset_access', identifier: d, name: d, attributes: {} })),
      },
      remediation: bqOpenAudits.length === 0 ? undefined : {
        summary: 'Remove public access; grant only named auditor SAs.',
        options: [{
          approach: 'Update dataset access via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Internal users of the open binding lose access.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per dataset.' },
          steps: ['Identify legitimate query users.', 'Grant via named groups.', 'Remove public access.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-EVC — Evaluating Configurations (GCP)
// =====================================================================
export async function collectMlaEvc(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // SCC finding lifecycle
  let activeCount = 0;
  let mutedCount = 0;
  try {
    const scc = await gcpAuth.googleClient<any>('securitycenter', 'v1');
    try {
      const r1 = await scc.projects.findings.list({
        parent: `projects/${ctx.project}/sources/-`,
        filter: 'state="ACTIVE"',
        pageSize: 200,
      });
      activeCount = (r1.data.listFindingsResults ?? []).length;
      const r2 = await scc.projects.findings.list({
        parent: `projects/${ctx.project}/sources/-`,
        filter: 'state="ACTIVE" AND mute="MUTED"',
        pageSize: 200,
      });
      mutedCount = (r2.data.listFindingsResults ?? []).length;
      evidence.push(ev('securitycenter.finding_lifecycle', { active: activeCount, muted: mutedCount }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.projects.findings.list', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.googleClient', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }

  // Cloud Build trigger inventory (proxy for IaC scanner invocation)
  let triggerCount = 0;
  try {
    const cb = await gcpAuth.googleClient<any>('cloudbuild', 'v1');
    const r = await cb.projects.triggers.list({ projectId: ctx.project });
    triggerCount = (r.data.triggers ?? []).length;
    evidence.push(ev('cloudbuild.trigger_count', { count: triggerCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudbuild.projects.triggers.list', 'cloudbuild.builds.list (roles/cloudbuild.builds.viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.scc.finding_triage_active',
      passed: activeCount === 0 || (activeCount - mutedCount) / Math.max(1, activeCount) < 0.5,
      severity: 'medium',
      current: {
        summary: `${activeCount} active SCC finding(s); ${mutedCount} muted with justification.`,
        observations: { active: activeCount, muted: mutedCount },
      },
      target: { summary: 'Active findings are being triaged. Mute count tracks documented exceptions.', rationale: 'NIST CA-7. Persistent evaluation requires triage cadence.' },
      gap: (activeCount === 0 || (activeCount - mutedCount) / Math.max(1, activeCount) < 0.5) ? undefined : {
        description: 'Most findings stuck active — triage loop is broken.',
        affected_resources: [{ type: 'google_scc_finding', identifier: 'aggregate', attributes: { active: activeCount, muted: mutedCount } }],
      },
      remediation: (activeCount === 0 || (activeCount - mutedCount) / Math.max(1, activeCount) < 0.5) ? undefined : {
        summary: 'Establish triage cadence + route findings to ticketing.',
        options: [{
          approach: 'SCC notification config → Pub/Sub → ticketing.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Pub/Sub charges.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Notification config + Cloud Function consumer.' },
          steps: ['Create SCC notification config.', 'Cloud Function consumes Pub/Sub messages.', 'Function creates tickets in JIRA/etc.'],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party CNAPP (Wiz, Lacework, Prisma Cloud)', description: 'External tool drives triage.', evidence_required: ['Representative finding lifecycle export'], detected: false },
      ],
      nist_controls: ['ca-7','si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-EIS', relationship: 'shares-remediation', note: 'EIS = enforcement; MLA-EVC = evaluation cadence.' },
        { ksi_id: 'KSI-SVC-EIS', relationship: 'shares-remediation', note: 'Same closed-loop.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-LET — Logging Event Types (GCP)
// =====================================================================
export async function collectMlaLet(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchLogInventory(ctx);

  const expectedDataAccessServices = ['cloudkms.googleapis.com', 'iam.googleapis.com', 'storage.googleapis.com', 'secretmanager.googleapis.com', 'bigquery.googleapis.com'];
  const missingDataAccess = expectedDataAccessServices.filter((s) => !inv.dataAccessLoggingForServices.has(s));

  const findings = [
    finding({
      rule: 'gcp.audit.data_access_logging_for_sensitive_services',
      passed: missingDataAccess.length === 0,
      severity: 'high',
      current: {
        summary: missingDataAccess.length === 0
          ? `Data Access logging enabled for all sensitive services: ${expectedDataAccessServices.join(', ')}.`
          : `Missing Data Access logging for: ${missingDataAccess.join(', ')}.`,
        observations: { enabled_for: Array.from(inv.dataAccessLoggingForServices), missing: missingDataAccess },
      },
      target: { summary: 'DATA_READ + DATA_WRITE audit logs enabled for cloudkms, iam, storage, secretmanager, bigquery.', rationale: 'NIST AU-2, AU-3. Default audit config does NOT include Data Access; explicit enable required for sensitive services.' },
      gap: missingDataAccess.length === 0 ? undefined : {
        description: 'Sensitive-service data access is unobservable.',
        affected_resources: missingDataAccess.map<AffectedResource>((s) => ({
          type: 'google_project_iam_audit_config', identifier: `${ctx.project}/${s}`, name: s, attributes: {},
        })),
      },
      remediation: missingDataAccess.length === 0 ? undefined : {
        summary: 'Configure audit_config blocks for each service.',
        options: [{
          approach: 'Apply google_project_iam_audit_config via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Cloud Logging ingest charges.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform per service.' },
          steps: ['Apply Terraform for each missing service.', 'Verify logs flowing.', 'Update SIEM consumer for new log types.'],
          example_code: `resource "google_project_iam_audit_config" "kms" {
  project = var.project_id
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','au-3','au-12'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SUS', relationship: 'shares-remediation', note: 'Data access logging is the IAM-SUS detection source.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-OSM — Operating SIEM Capability (GCP)
// =====================================================================
export async function collectMlaOsm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchLogInventory(ctx);

  const pubsubSinks = inv.sinks.filter((s: any) => /^pubsub\.googleapis\.com/.test(s.destination ?? ''));
  const bqSinks = inv.sinks.filter((s: any) => /^bigquery\.googleapis\.com/.test(s.destination ?? ''));
  const storageSinks = inv.sinks.filter((s: any) => /^storage\.googleapis\.com/.test(s.destination ?? ''));

  // Heuristic: a Pub/Sub sink is often the SIEM-export plumbing
  const siemExportPresent = pubsubSinks.length >= 1;

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Chronicle SIEM (Google-native)',
      description: 'Chronicle ingests logs at the org level; direct API detection requires Chronicle backend ID + auth not in standard GCP API.',
      evidence_required: ['Chronicle tenant + backend ID', 'Sample query showing recent ingestion'],
      detected: false,
      detection_signals: ['Direct Chronicle API detection requires separate credentials.'],
    },
    {
      via: 'Splunk via Pub/Sub Splunk Add-on',
      description: 'Pub/Sub topic ingested by Splunk Add-on for GCP.',
      evidence_required: ['Pub/Sub subscription IAM with Splunk SA', 'Splunk dashboard showing GCP data', 'Ingestion lag'],
      detected: false,
      detection_signals: [],
    },
    {
      via: 'Datadog (Pub/Sub or direct API)',
      description: 'Logs forwarded to Datadog via Pub/Sub.',
      evidence_required: ['Pub/Sub binding to datadog-log-forwarder SA', 'Datadog dashboard'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.siem.export_plumbing_present',
      passed: siemExportPresent || bqSinks.length >= 1,
      severity: 'high',
      current: {
        summary: siemExportPresent
          ? `${pubsubSinks.length} Pub/Sub sink(s) present (likely SIEM export plumbing).`
          : (bqSinks.length >= 1 ? `${bqSinks.length} BigQuery sink(s) — logs available for centralized query.` : 'No SIEM-export sinks (Pub/Sub or BigQuery) detected.'),
        observations: {
          pubsub_sinks: pubsubSinks.length,
          bq_sinks: bqSinks.length,
          storage_sinks: storageSinks.length,
        },
      },
      target: { summary: 'At least one sink routes audit logs to BigQuery, Pub/Sub (for SIEM ingest), or storage (for long-term).', rationale: 'NIST AU-6.' },
      gap: (siemExportPresent || bqSinks.length >= 1) ? undefined : {
        description: 'No centralized log destination — analysis is per-service ad-hoc.',
        affected_resources: [{ type: 'google_logging_project_sink', identifier: 'none-siem', attributes: {} }],
      },
      remediation: (siemExportPresent || bqSinks.length >= 1) ? undefined : {
        summary: 'Create a sink to BigQuery (cheap, queryable) and/or Pub/Sub (for SIEM ingest).',
        options: [{
          approach: 'BigQuery sink for ad-hoc analysis + Pub/Sub for SIEM forwarding.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'BQ + Pub/Sub usage.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Sink + downstream consumer.' },
          steps: ['Create BQ dataset + Pub/Sub topic.', 'Create sinks with appropriate filters.', 'Wire SIEM ingest.'],
          example_code: `resource "google_logging_project_sink" "siem" {
  name        = "to-siem"
  destination = "pubsub.googleapis.com/projects/$\${var.project_id}/topics/siem-ingest"
  filter      = "logName:cloudaudit.googleapis.com OR severity>=NOTICE"
  unique_writer_identity = true
}`,
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['au-6','au-6.1'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-MLA-RVL — Reviewing Logs (GCP)
// =====================================================================
export async function collectMlaRvl(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let savedQueriesCount = 0;
  try {
    const bq = await gcpAuth.googleClient<any>('bigquery', 'v2');
    // bq.jobs queries don't expose "saved queries" via standard API — these live in Console.
    // Surface dataset count + recent jobs as proxy.
    const dl = await bq.datasets.list({ projectId: ctx.project });
    const datasetCount = dl.data.datasets?.length ?? 0;
    evidence.push(ev('bigquery.review_tooling', { dataset_count: datasetCount }));
    savedQueriesCount = datasetCount; // proxy
  } catch (e) { warnings.push(diagnoseGcpError(e, 'bigquery.datasets.list', 'bigquery.datasets.get (roles/bigquery.metadataViewer)')); }

  // Monitoring dashboards as another review primitive
  let dashboardCount = 0;
  try {
    const monitoring = await gcpAuth.googleClient<any>('monitoring', 'v1');
    const r = await monitoring.projects.dashboards.list({ parent: `projects/${ctx.project}`, pageSize: 50 });
    dashboardCount = (r.data.dashboards ?? []).length;
    evidence.push(ev('monitoring.dashboards', { count: dashboardCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'monitoring.projects.dashboards.list', 'monitoring.dashboards.list (roles/monitoring.viewer)')); }

  const reviewToolingPresent = savedQueriesCount >= 1 || dashboardCount >= 1;

  const findings = [
    finding({
      rule: 'gcp.log_review.tooling_present',
      passed: reviewToolingPresent,
      severity: 'medium',
      current: {
        summary: reviewToolingPresent
          ? `Review tooling present: ${savedQueriesCount} BQ dataset(s), ${dashboardCount} dashboard(s).`
          : 'No review tooling found (BQ datasets / dashboards).',
        observations: { bq_datasets_proxy: savedQueriesCount, dashboards: dashboardCount },
      },
      target: { summary: 'At least one BigQuery dataset / saved query OR Monitoring dashboard supports log review.', rationale: 'NIST AU-6. Reviewability is a tooling problem first.' },
      gap: reviewToolingPresent ? undefined : {
        description: 'No saved queries / dashboards for routine log review.',
        affected_resources: [{ type: 'google_monitoring_dashboard', identifier: 'none', attributes: {} }],
      },
      remediation: reviewToolingPresent ? undefined : {
        summary: 'Author saved BQ queries / Looker Studio dashboards for routine log review.',
        options: [{
          approach: 'Set up BQ audit-logs dataset + saved queries.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'BQ scan charges.' },
          availability_impact: { level: 'none', notes: 'Pure analysis.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Query authoring.' },
          steps: ['Sink audit logs to BQ.', 'Author saved queries (privileged sign-ins, IAM-grant changes, etc.).', 'Schedule review cadence.'],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party SIEM saved dashboards (Splunk, Datadog, Chronicle, etc.)', description: 'Review tooling can live in SIEM.', evidence_required: ['SIEM dashboard exports', 'Review-meeting minutes'], detected: false },
      ],
      nist_controls: ['au-6'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-INR-RIR — Reviewing IR Procedures (GCP, HYBRID)
// =====================================================================
export async function collectInrRir(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Notification channels + alert policies + Eventarc triggers
  let notificationChannels = 0;
  let alertPolicies = 0;
  let eventarcTriggers = 0;
  try {
    const monitoring = await gcpAuth.googleClient<any>('monitoring', 'v3');
    try {
      const nc = await monitoring.projects.notificationChannels.list({ name: `projects/${ctx.project}` });
      notificationChannels = (nc.data.notificationChannels ?? []).length;
    } catch { /* */ }
    try {
      const ap = await monitoring.projects.alertPolicies.list({ name: `projects/${ctx.project}` });
      alertPolicies = (ap.data.alertPolicies ?? []).length;
    } catch { /* */ }
    evidence.push(ev('monitoring.alert_infra', { channels: notificationChannels, policies: alertPolicies }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'monitoring.projects.notificationChannels.list/alertPolicies.list', 'monitoring.alertPolicies.list (roles/monitoring.viewer)')); }

  try {
    const eventarc = await gcpAuth.googleClient<any>('eventarc', 'v1');
    const r = await eventarc.projects.locations.triggers.list({ parent: `projects/${ctx.project}/locations/-`, pageSize: 100 });
    eventarcTriggers = (r.data.triggers ?? []).length;
    evidence.push(ev('eventarc.triggers_for_rir', { count: eventarcTriggers }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'eventarc.projects.locations.triggers.list', 'eventarc.triggers.list (roles/eventarc.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'PagerDuty / OpsGenie via monitoring notification channels',
      description: 'GCP Monitoring routes alerts to incident-management vendor.',
      evidence_required: ['Notification channel config showing PagerDuty', 'Sample paging event'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.alert_routing.plumbing_present',
      passed: alertPolicies >= 1 && notificationChannels >= 1,
      severity: 'high',
      current: {
        summary: alertPolicies >= 1 && notificationChannels >= 1
          ? `${alertPolicies} alert policy/policies; ${notificationChannels} notification channel(s); ${eventarcTriggers} Eventarc trigger(s).`
          : `Insufficient alert plumbing: ${alertPolicies} policies, ${notificationChannels} channels.`,
        observations: { alert_policies: alertPolicies, notification_channels: notificationChannels, eventarc_triggers: eventarcTriggers },
      },
      target: { summary: '≥1 alert policy with ≥1 notification channel attached; downstream Eventarc / Pub/Sub consumers for automated response.', rationale: 'NIST IR-4.' },
      gap: (alertPolicies >= 1 && notificationChannels >= 1) ? undefined : {
        description: 'No alert routing infrastructure.',
        affected_resources: [{ type: 'google_monitoring_alert_policy', identifier: 'none', attributes: {} }],
      },
      remediation: (alertPolicies >= 1 && notificationChannels >= 1) ? undefined : {
        summary: 'Create notification channels + alert policies for critical metrics + SCC notification configs.',
        options: [{
          approach: 'Set up via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Per-API charges.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Policy authoring + channel setup.' },
          steps: ['Create notification channels for PagerDuty/Slack/email.', 'Attach to critical alert policies.', 'Test by triggering an alert.'],
          example_code: `resource "google_monitoring_notification_channel" "pagerduty" {
  type = "pagerduty"
  labels = { service_key = var.pagerduty_key }
}
resource "google_monitoring_alert_policy" "errors" {
  display_name          = "High error rate"
  notification_channels = [google_monitoring_notification_channel.pagerduty.name]
  conditions { ... }
}`,
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ir-4','ir-4.1'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}
