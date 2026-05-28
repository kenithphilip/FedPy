/**
 * GCP KSI HYBRID collectors — currently-uncovered indicators.
 *
 * Each KSI here is a "persistently review the effectiveness of X" or "mitigate X"
 * obligation (MUST at Low and Moderate from the 20x machine-readable data; High
 * derived from the NIST 800-53 Rev5 baseline via the requirement controls — see
 * docs/analysis/ksi-gaps.md). KSI-SVC-PRR is not-applicable at High per the source.
 *
 * These emit the api-testable PROXY half of each HYBRID requirement (the read-only
 * GCP signal that the underlying capability exists). The human review artifact is
 * attached via process_artifacts_required in ksi-map.ts.
 *
 * STRICTLY READ-ONLY: list/get only. Every call is wrapped with diagnoseGcpError so
 * a PERMISSION_DENIED names the exact role/permission to grant.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, Finding, KeyWord } from '../../core/envelope.ts';
import { finding, severityForKeyWord } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

function tierKeyWord(): KeyWord { return 'MUST'; }

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

function block(evidence: RawEvidence[], findings: Finding[], warnings: string[], project: string): ProviderBlock {
  return { provider: 'gcp', project_id: project, evidence, findings, warnings };
}

// =====================================================================
// KSI-CMT-RVP — Reviewing Change Procedures (asset-change monitoring active)
// =====================================================================
export async function collectCmtRvp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let feedCount = 0;
  try {
    const cloudasset = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    const r = await cloudasset.feeds.list({ parent: `projects/${ctx.project}` });
    feedCount = (r.data.feeds ?? []).length;
    evidence.push(ev('cloudasset.feeds.list', { count: feedCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.feeds.list', 'cloudasset.feeds.list (roles/cloudasset.viewer)')); }

  const passed = feedCount > 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.cmt.change_monitoring_active',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Asset-change monitoring active: ${feedCount} Cloud Asset Inventory feed(s) emit real-time change events.`
        : 'No Cloud Asset Inventory feeds found — no automated detection of out-of-procedure changes.',
      observations: { asset_feeds: feedCount },
    },
    target: {
      summary: 'Resource changes are continuously monitored so out-of-procedure changes are detected; the periodic human review of change-procedure effectiveness is the process half.',
      rationale: 'KSI-CMT-RVP / NIST CM-3, CM-5. An automated change-detection signal is required to review change-procedure effectiveness.',
    },
    gap: passed ? undefined : {
      description: 'Without asset-change feeds (or an equivalent drift detector) there is no automated evidence that change procedures are enforced.',
      affected_resources: [{ type: 'gcp_cloud_asset_inventory', identifier: ctx.project, name: 'Cloud Asset Inventory' }],
    },
    remediation: passed ? undefined : {
      summary: 'Create a Cloud Asset Inventory feed (or wire a drift detector) for change-controlled asset types.',
      options: [{
        approach: 'Create a Cloud Asset feed to Pub/Sub for the asset types under change control.',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'none', notes: 'Asset feeds are low/no cost.' },
        availability_impact: { level: 'none', notes: 'Read-only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Create feed + sink.' },
        steps: ['Create a Cloud Asset Inventory feed to a Pub/Sub topic.', 'Alert on changes that bypass the change process.', 'Review change-procedure effectiveness on cadence.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Drift detection via Wiz / Terraform Cloud / Config Controller', description: 'A CNAPP or GitOps drift detector flags resources diverging from desired state — equivalent change-enforcement evidence.', evidence_required: ['Drift tool + scope', 'Sample drift alert + resolution'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cm-3', 'cm-3.2', 'cm-3.4', 'cm-5', 'cm-7.1', 'cm-9'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-INR-AAR — After Action Reports (automated alerting present)
// =====================================================================
export async function collectInrAar(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let alertPolicies = 0;
  let enabledPolicies = 0;
  try {
    const monitoring = await gcpAuth.googleClient<any>('monitoring', 'v3');
    const r = await monitoring.projects.alertPolicies.list({ name: `projects/${ctx.project}` });
    for (const p of r.data.alertPolicies ?? []) {
      alertPolicies++;
      if (p.enabled !== false) enabledPolicies++;
    }
    evidence.push(ev('monitoring.alertPolicies.list', { total: alertPolicies, enabled: enabledPolicies }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'monitoring.alertPolicies.list', 'monitoring.alertPolicies.list (roles/monitoring.viewer)')); }

  const passed = enabledPolicies > 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.inr.automated_alerting_present',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `${enabledPolicies}/${alertPolicies} Cloud Monitoring alert policy(ies) enabled — incidents are detected automatically, feeding after-action reports.`
        : `No enabled Cloud Monitoring alert policies (${alertPolicies} total). Incidents may not be detected automatically.`,
      observations: { alert_policies: alertPolicies, enabled: enabledPolicies },
    },
    target: {
      summary: 'Incidents are automatically detected and routed, producing the records that feed after-action reviews.',
      rationale: 'KSI-INR-AAR / NIST IR-3, IR-4, IR-4.1, IR-8.',
    },
    gap: passed ? undefined : {
      description: 'Missing automated alerting reduces the fidelity of incident records that feed after-action reviews.',
      affected_resources: [{ type: 'gcp_monitoring', identifier: ctx.project, name: 'Cloud Monitoring' }],
    },
    remediation: passed ? undefined : {
      summary: 'Create Cloud Monitoring alert policies routed to your incident-response tool.',
      options: [{
        approach: 'Define alert policies + notification channels (PagerDuty/Opsgenie/Pub/Sub).',
        mechanism: 'terraform', owner_team: 'Security',
        cost_impact: { level: 'none', notes: 'Alerting is low cost.' },
        availability_impact: { level: 'none', notes: 'Detective only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Policies + channels.' },
        steps: ['Create alert policies for security/availability signals.', 'Add notification channels to your IR tool.', 'Capture incidents + produce after-action reports.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'PagerDuty / Opsgenie / Splunk SOAR', description: 'An external IR platform ingests alerts and drives the response + after-action workflow.', evidence_required: ['IR platform + integration', 'Sample incident + after-action report'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-8'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-INR-RPI — Reviewing Past Incidents (durable log retention via sinks)
// =====================================================================
export async function collectInrRpi(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let sinks = 0;
  let durableSinks = 0;
  try {
    const logging = await gcpAuth.googleClient<any>('logging', 'v2');
    const r = await logging.projects.sinks.list({ parent: `projects/${ctx.project}` });
    for (const s of r.data.sinks ?? []) {
      sinks++;
      const dest = String(s.destination ?? '');
      if (dest.startsWith('storage.googleapis.com') || dest.startsWith('bigquery.googleapis.com') || dest.includes('logging.googleapis.com/projects')) durableSinks++;
    }
    evidence.push(ev('logging.sinks.list', { total: sinks, durable: durableSinks }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'logging.sinks.list', 'logging.sinks.list (roles/logging.viewer)')); }

  const passed = durableSinks > 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.inr.incident_history_retained',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Durable incident history available: ${durableSinks}/${sinks} log sink(s) export to GCS/BigQuery/log buckets for long-term retention.`
        : `No durable log export sink found (${sinks} sink(s)). Past-incident review may lack a complete activity record.`,
      observations: { sinks, durable_sinks: durableSinks },
    },
    target: {
      summary: 'Activity/audit logs are retained long enough to review past incidents for patterns.',
      rationale: 'KSI-INR-RPI / NIST IR-4, IR-5, AU-11.',
    },
    gap: passed ? undefined : {
      description: 'Without a durable export sink, logs may age out before a post-incident review can find patterns.',
      affected_resources: [{ type: 'gcp_logging', identifier: ctx.project, name: 'Cloud Logging' }],
    },
    remediation: passed ? undefined : {
      summary: 'Create a log sink to GCS/BigQuery with retention covering your incident-review window.',
      options: [{
        approach: 'Create an aggregated log sink to BigQuery or GCS with a retention/lifecycle policy.',
        mechanism: 'terraform', owner_team: 'Security',
        cost_impact: { level: 'low', notes: 'Storage of exported logs.' },
        availability_impact: { level: 'none', notes: 'Logging only.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Create sink + retention.' },
        steps: ['Create a log sink to BigQuery/GCS.', 'Set retention to your incident-review window.', 'Verify security/audit logs are included.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'SIEM long-term retention', description: 'A SIEM retaining GCP audit logs provides the searchable incident history.', evidence_required: ['SIEM retention policy', 'Sample historical incident query'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-5', 'ir-8'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-RPL-ARP — Aligning Recovery Plan (regional HA posture)
// =====================================================================
export async function collectRplArp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  const zonal: string[] = [];
  let total = 0;
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      total++;
      if (i.settings?.availabilityType !== 'REGIONAL') zonal.push(i.name);
    }
    evidence.push(ev('sqladmin.recovery_posture', { total, zonal }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  const passed = zonal.length === 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.rpl.alternate_processing_posture',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `Alternate-processing posture present: all ${total} Cloud SQL instance(s) are REGIONAL (HA).`
        : `${zonal.length} of ${total} Cloud SQL instance(s) are ZONAL — no automatic alternate-processing site.`,
      observations: { total, zonal_instances: zonal },
    },
    target: {
      summary: 'Critical data stores run with regional/cross-region HA aligned to the recovery plan.',
      rationale: 'KSI-RPL-ARP / NIST CP-2, CP-6, CP-7, CP-10.',
    },
    gap: passed ? undefined : {
      description: 'Zonal data stores cannot meet recovery objectives assuming an alternate processing site.',
      affected_resources: zonal.map<AffectedResource>((n) => ({ type: 'gcp_sql_instance', identifier: n, name: n, attributes: { availability_type: 'ZONAL' } })),
    },
    remediation: passed ? undefined : {
      summary: 'Set Cloud SQL availabilityType to REGIONAL and document cross-region recovery.',
      options: [{
        approach: 'Set settings.availabilityType = REGIONAL via Terraform; add a cross-region replica if RTO requires.',
        mechanism: 'terraform', owner_team: 'SRE',
        cost_impact: { level: 'medium', notes: 'Regional HA doubles instance cost.' },
        availability_impact: { level: 'low', notes: 'Conversion may require a restart window.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'days', notes: 'Per store incl. validation.' },
        steps: ['Set availabilityType = REGIONAL.', 'Add cross-region read replica for the recovery site if needed.', 'Update the recovery plan to match.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Cross-region backup + documented restore runbook', description: 'Cross-region backups + a tested restore runbook can satisfy alternate-processing alignment without standing standby compute.', evidence_required: ['Cross-region backup config', 'DR runbook + last restore test'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cp-2', 'cp-6', 'cp-7', 'cp-10', 'cp-10.2'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-RPL-RRO — Reviewing Recovery Objectives (automated backups codify RPO)
// =====================================================================
export async function collectRplRro(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let total = 0;
  let withBackups = 0;
  const withoutBackups: string[] = [];
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      total++;
      if (i.settings?.backupConfiguration?.enabled) withBackups++;
      else withoutBackups.push(i.name);
    }
    evidence.push(ev('sqladmin.backup_configuration', { total, with_backups: withBackups, without: withoutBackups }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  const passed = total === 0 ? false : withoutBackups.length === 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.rpl.recovery_objectives_codified',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `All ${total} Cloud SQL instance(s) have automated backups enabled — backup cadence codifies an effective RPO to review against targets.`
        : `${withoutBackups.length} of ${total} Cloud SQL instance(s) lack automated backups. RPO is not codified for automated review.`,
      observations: { total, with_backups: withBackups, without_backups: withoutBackups },
    },
    target: {
      summary: 'Automated backup schedules encode the effective RPO so it can be reviewed against documented RTO/RPO targets.',
      rationale: 'KSI-RPL-RRO / NIST CP-2.3, CP-9, CP-10.',
    },
    gap: passed ? undefined : {
      description: 'Instances without automated backups have no codified RPO to review against objectives.',
      affected_resources: withoutBackups.map<AffectedResource>((n) => ({ type: 'gcp_sql_instance', identifier: n, name: n, attributes: { automated_backups: false } })),
    },
    remediation: passed ? undefined : {
      summary: 'Enable automated backups with a retention window matching your RPO.',
      options: [{
        approach: 'Set settings.backupConfiguration.enabled = true + retention via Terraform.',
        mechanism: 'terraform', owner_team: 'SRE',
        cost_impact: { level: 'low', notes: 'Backup storage.' },
        availability_impact: { level: 'none', notes: 'Backups are non-disruptive.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'hours', notes: 'Per instance.' },
        steps: ['Enable automated backups on each Cloud SQL instance.', 'Set retention/PITR to match your RPO.', 'Compare cadence to documented RPO in the recovery-objective review.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Backup & DR Service / scheduled snapshots + RPO register', description: 'GCP Backup & DR or scheduled disk snapshots with retention can codify RPO outside Cloud SQL.', evidence_required: ['Backup schedule config', 'RPO/RTO register'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['cp-2.3', 'cp-9', 'cp-10'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-SCR-MIT — Mitigating Supply Chain Risk (Binary Authorization enforced)
// =====================================================================
export async function collectScrMit(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  let evalMode = 'unknown';
  let enforced = false;
  try {
    const ba = await gcpAuth.googleClient<any>('binaryauthorization', 'v1');
    const r = await ba.projects.getPolicy({ name: `projects/${ctx.project}/policy` });
    const dflt = r.data.defaultAdmissionRule ?? {};
    evalMode = r.data.globalPolicyEvaluationMode ?? dflt.evaluationMode ?? 'unknown';
    // Enforced = not the permissive ALWAYS_ALLOW default. Boolean() guards against
    // undefined when neither mode field is present (e.g. no policy configured).
    enforced = Boolean(
      (dflt.evaluationMode && dflt.evaluationMode !== 'ALWAYS_ALLOW') ||
      (dflt.enforcementMode && dflt.enforcementMode !== 'ALWAYS_ALLOW'),
    );
    evidence.push(ev('binaryauthorization.getPolicy', { global_mode: evalMode, default_rule: dflt, enforced }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'binaryauthorization.projects.getPolicy', 'binaryauthorization.policy.get (roles/binaryauthorization.policyViewer)')); }

  const passed = enforced;
  const findings: Finding[] = [finding({
    rule: 'gcp.scr.image_admission_enforced',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? 'Supply-chain admission control active: Binary Authorization enforces attestation/allowlist on image deploys.'
        : `Binary Authorization not enforcing (default rule allows all). Untrusted/unscanned images can be deployed.`,
      observations: { global_evaluation_mode: evalMode, enforced },
    },
    target: {
      summary: 'Only attested/scanned images from trusted sources are admitted, mitigating supply-chain risk at deploy time.',
      rationale: 'KSI-SCR-MIT / NIST SA-10, SA-11, SR-5, SR-6, SI-7.1.',
    },
    gap: passed ? undefined : {
      description: 'Without Binary Authorization enforcement, vulnerable or untrusted upstream images can be deployed.',
      affected_resources: [{ type: 'gcp_binary_authorization_policy', identifier: ctx.project, name: 'Binary Authorization policy', attributes: { evaluation_mode: evalMode } }],
    },
    remediation: passed ? undefined : {
      summary: 'Enable Binary Authorization with attestation requirements + Artifact Registry vulnerability scanning.',
      options: [{
        approach: 'Set the default admission rule to REQUIRE_ATTESTATION and require an attestor from your signing pipeline.',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'low', notes: 'Scanning + attestation pipeline.' },
        availability_impact: { level: 'medium', notes: 'Enforcement can block unsigned deploys — stage in dry-run first.' },
        customer_visible: { level: 'none', notes: 'Internal.' },
        effort_estimate: { magnitude: 'days', notes: 'Policy + attestor + CI signing.' },
        steps: ['Enable Artifact Registry/Container Analysis vulnerability scanning.', 'Create an attestor + signing step in CI (cosign/Sigstore).', 'Set Binary Authorization default rule to REQUIRE_ATTESTATION (dry-run, then enforce).'],
      }],
    },
    alternative_satisfiers: [
      { via: 'Wiz / Prisma / Snyk / Anchore + Sigstore cosign', description: 'A dedicated scanner plus signing/attestation provides equivalent supply-chain mitigation.', evidence_required: ['Scanner + registry coverage', 'Signing/attestation policy'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['ac-20', 'sa-9', 'sa-10', 'sa-11', 'sr-5', 'sr-6', 'si-7.1'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}

// =====================================================================
// KSI-SVC-PRR — Preventing Residual Risk (public-access prevention enforced)
// =====================================================================
export async function collectSvcPrr(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw = tierKeyWord();

  const bucketsNotEnforced: string[] = [];
  let bucketCount = 0;
  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const r = await storage.buckets.list({ project: ctx.project });
    for (const b of r.data.items ?? []) {
      bucketCount++;
      const pap = b.iamConfiguration?.publicAccessPrevention;
      if (pap !== 'enforced') bucketsNotEnforced.push(b.name);
    }
    evidence.push(ev('storage.public_access_prevention', { buckets: bucketCount, not_enforced: bucketsNotEnforced }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  const publicDbs: string[] = [];
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      if (i.settings?.ipConfiguration?.ipv4Enabled) publicDbs.push(i.name);
    }
    evidence.push(ev('sqladmin.public_ip', { public_ip_instances: publicDbs }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  const exposures = bucketsNotEnforced.length + publicDbs.length;
  const passed = exposures === 0;
  const findings: Finding[] = [finding({
    rule: 'gcp.svc.no_residual_exposure_via_shared_resources',
    passed,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: passed
        ? `No residual exposure found: all ${bucketCount} bucket(s) enforce public-access prevention and no Cloud SQL instance has a public IP.`
        : `${bucketsNotEnforced.length} bucket(s) do not enforce public-access prevention; ${publicDbs.length} Cloud SQL instance(s) have a public IP.`,
      observations: { buckets: bucketCount, buckets_not_enforced: bucketsNotEnforced, public_ip_dbs: publicDbs },
    },
    target: {
      summary: 'Information is not exposed to unauthorized parties through shared resources (no public buckets, no public DB IPs).',
      rationale: 'KSI-SVC-PRR / NIST SC-4 (information in shared resources).',
    },
    gap: passed ? undefined : {
      description: 'Public buckets / public DB IPs can leak residual federal data through shared infrastructure.',
      affected_resources: [
        ...bucketsNotEnforced.map<AffectedResource>((n) => ({ type: 'gcp_storage_bucket', identifier: n, name: n, attributes: { public_access_prevention: 'not enforced' } })),
        ...publicDbs.map<AffectedResource>((n) => ({ type: 'gcp_sql_instance', identifier: n, name: n, attributes: { public_ip: true } })),
      ],
    },
    remediation: passed ? undefined : {
      summary: 'Enforce public-access prevention on buckets and disable public IPs on Cloud SQL.',
      options: [{
        approach: 'Set iamConfiguration.publicAccessPrevention = enforced; disable ipv4Enabled and use Private IP.',
        mechanism: 'terraform', owner_team: 'Platform',
        cost_impact: { level: 'none', notes: 'No cost.' },
        availability_impact: { level: 'medium', notes: 'Disabling public IP can break clients — verify private connectivity first.' },
        customer_visible: { level: 'low', notes: 'Only if an integration relied on public access.' },
        effort_estimate: { magnitude: 'hours', notes: 'Per resource.' },
        steps: ['Set publicAccessPrevention = enforced on all buckets + the org policy.', 'Disable Cloud SQL public IP; use Private Service Connect / Private IP.', 'Verify clients use private connectivity.'],
      }],
    },
    alternative_satisfiers: [
      { via: 'CSPM (Wiz / Prisma / Orca) public-exposure policy', description: 'A CSPM continuously flags publicly exposed storage/databases and can block via guardrails.', evidence_required: ['CSPM exposure policy', 'Sample exposure finding + resolution'], detected: false, detection_signals: [] },
    ],
    nist_controls: ['sc-4'],
  })];
  return block(evidence, findings, warnings, ctx.project);
}
