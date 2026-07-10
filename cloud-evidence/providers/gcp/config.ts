/**
 * GCP config-domain CNA collectors.
 * Covers KSI-CNA-EIS (drift enforcement) and KSI-CNA-IBP (best practices via SCC).
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
// KSI-CNA-EIS — Enforcing Intended State
// =====================================================================
export async function collectCnaEis(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Asset Inventory feeds (real-time change events)
  let feedCount = 0;
  try {
    const cloudasset = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    const r = await cloudasset.feeds.list({ parent: `projects/${ctx.project}` });
    feedCount = r.data.feeds?.length ?? 0;
    evidence.push(ev('cloudasset.feeds', { count: feedCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.feeds.list', 'cloudasset.feeds.list (roles/cloudasset.viewer)')); }

  // Policy Controller / Anthos Config Management on GKE clusters
  let policyControllerEnabled = false;
  const clustersWithoutPC: string[] = [];
  try {
    const gkehub = await gcpAuth.googleClient<any>('gkehub', 'v1');
    const r = await gkehub.projects.locations.features.list({ parent: `projects/${ctx.project}/locations/global` });
    const features = r.data.resources ?? [];
    const pc = features.find((f: any) => /policycontroller/.test(f.name ?? ''));
    if (pc) {
      policyControllerEnabled = true;
      const membership = pc.membershipStates ?? {};
      for (const [m, s] of Object.entries<any>(membership)) {
        if (s.policycontroller?.state?.componentStates?.installManager?.state !== 'INSTALLED') {
          clustersWithoutPC.push(m);
        }
      }
    }
    evidence.push(ev('gkehub.policy_controller', { enabled: policyControllerEnabled, clusters_without_pc: clustersWithoutPC }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'gkehub.projects.locations.features.list', 'gkehub.features.list (roles/gkehub.viewer)')); }

  // SCC findings (auto-remediation status proxy)
  let muteConfigsCount = 0;
  let notificationConfigsCount = 0;
  try {
    const scc = await gcpAuth.googleClient<any>('securitycenter', 'v1');
    try {
      const m = await scc.organizations.muteConfigs.list({ parent: `projects/${ctx.project}` });
      muteConfigsCount = m.data.muteConfigs?.length ?? 0;
    } catch { /* may not have org-level */ }
    try {
      const n = await scc.projects.notificationConfigs.list({ parent: `projects/${ctx.project}` });
      notificationConfigsCount = n.data.notificationConfigs?.length ?? 0;
    } catch { /* may not have permission */ }
    evidence.push(ev('securitycenter.config_counts', { muteConfigs: muteConfigsCount, notificationConfigs: notificationConfigsCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.muteConfigs.list/notificationConfigs.list', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }

  const findings = [
    finding({
      rule: 'gcp.cloudasset.feeds_active',
      passed: feedCount >= 1,
      severity: 'high',
      current: {
        summary: feedCount >= 1
          ? `${feedCount} Asset Inventory feed(s) active — real-time change events flowing.`
          : 'No Asset Inventory feeds — change events are not being routed for drift response.',
        observations: { feed_count: feedCount },
      },
      target: { summary: 'At least one asset feed routes resource + IAM-policy changes to a Pub/Sub topic consumed by a remediation function.', rationale: 'NIST CA-7. Asset feeds are the GCP-native drift signal source.' },
      gap: feedCount >= 1 ? undefined : {
        description: 'Without feeds, drift detection lags by hours/days.',
        affected_resources: [{ type: 'google_cloud_asset_project_feed', identifier: 'none', attributes: {} }],
      },
      remediation: feedCount >= 1 ? undefined : {
        summary: 'Create asset feed routing changes to a Pub/Sub topic.',
        options: [{
          approach: 'Create feed via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Pub/Sub message charges.' },
          availability_impact: { level: 'none', notes: 'Pure observation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Feed + consumer.' },
          steps: ['Create Pub/Sub topic.', 'Create asset feed.', 'Wire downstream consumer (Cloud Function for auto-remediation or SIEM ingest).'],
          example_code: `resource "google_cloud_asset_project_feed" "all" {
  project      = var.project_id
  feed_id      = "all-changes"
  content_type = "RESOURCE"
  asset_types  = [".*"]
  feed_output_config {
    pubsub_destination { topic = google_pubsub_topic.asset_changes.id }
  }
}`,
          references: [{ title: 'Cloud Asset Inventory feeds', url: 'https://cloud.google.com/asset-inventory/docs/monitoring-asset-changes' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ca-7','ca-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CMT-LMC', relationship: 'shares-remediation', note: 'Asset feeds are also change-logging.' },
      ],
    }),

    finding({
      rule: 'gcp.policy_controller_installed_on_prod_clusters',
      passed: policyControllerEnabled && clustersWithoutPC.length === 0,
      severity: 'medium',
      current: {
        summary: policyControllerEnabled
          ? (clustersWithoutPC.length === 0
            ? 'Policy Controller installed on all GKE clusters.'
            : `Policy Controller enabled but missing on ${clustersWithoutPC.length} cluster(s).`)
          : 'Policy Controller (Anthos Config Management) not enabled.',
        observations: { policy_controller_enabled: policyControllerEnabled, clusters_without_pc: clustersWithoutPC },
      },
      target: { summary: 'Policy Controller installed on every prod GKE cluster with ≥1 ConstraintTemplate + Constraint enforced.', rationale: 'NIST CM-7. Policy Controller is GCP\'s in-cluster admission control + drift prevention.' },
      gap: (policyControllerEnabled && clustersWithoutPC.length === 0) ? undefined : {
        description: 'Without Policy Controller, K8s workloads can violate org policies.',
        affected_resources: clustersWithoutPC.length
          ? clustersWithoutPC.map<AffectedResource>((c2: string) => ({
              type: 'google_container_cluster', identifier: c2, name: c2, attributes: {},
            }))
          : [{ type: 'gcp_project', identifier: ctx.project ?? 'project', name: 'Policy Controller not enabled on the fleet', attributes: { policy_controller_enabled: policyControllerEnabled } }],
      },
      remediation: (policyControllerEnabled && clustersWithoutPC.length === 0) ? undefined : {
        summary: 'Enable Policy Controller via fleet feature.',
        options: [{
          approach: 'Enable via gkehub feature + per-cluster membership.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Anthos Config Management license cost depending on tier.' },
          availability_impact: { level: 'medium', notes: 'Default-deny constraints block legitimate workloads; canary first.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Feature setup + constraint authoring.' },
          steps: ['Enable Policy Controller feature.', 'Add cluster to fleet.', 'Deploy baseline constraints (no privileged containers, image source allowlist, etc.).'],
          references: [{ title: 'Policy Controller', url: 'https://cloud.google.com/anthos-config-management/docs/concepts/policy-controller' }],
        }],
      },
      alternative_satisfiers: [
        { via: 'OPA Gatekeeper deployed directly (vs Anthos-managed)', description: 'Same admission controller, self-managed.', evidence_required: ['OPA Gatekeeper deployment manifests', 'sample constraint enforcement'], detected: false },
      ],
      nist_controls: ['ca-2.1','cm-7'],
    }),

    finding({
      rule: 'gcp.scc.notification_configs_present',
      passed: notificationConfigsCount >= 1,
      severity: 'medium',
      current: {
        summary: notificationConfigsCount >= 1
          ? `${notificationConfigsCount} SCC notification config(s) active.`
          : 'No SCC notification configs — findings are not routed for automation.',
        observations: { count: notificationConfigsCount },
      },
      target: { summary: 'SCC findings routed via at least one notification config to Pub/Sub.', rationale: 'NIST SI-4. Without routing, drift signals are not consumed.' },
      gap: notificationConfigsCount >= 1 ? undefined : {
        description: 'SCC findings not piped to automation.',
        affected_resources: [{ type: 'google_scc_notification_config', identifier: 'none', attributes: {} }],
      },
      remediation: notificationConfigsCount >= 1 ? undefined : {
        summary: 'Create SCC notification config (org-level).',
        options: [{
          approach: 'Configure via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Pub/Sub charges.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Create Pub/Sub topic.', 'Create notification config.', 'Subscribe downstream consumer (SIEM or remediation function).'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SUS', relationship: 'shares-remediation', note: 'SCC notification routing is the IAM-SUS plumbing.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-IBP — Implementing Best Practices (SCC posture)
// =====================================================================
export async function collectCnaIbp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let shaCriticalCount = 0;
  let shaHighCount = 0;
  let recommendationsCount = 0;

  try {
    const scc = await gcpAuth.googleClient<any>('securitycenter', 'v1');
    try {
      const r = await scc.projects.findings.list({
        parent: `projects/${ctx.project}/sources/-`,
        filter: 'state="ACTIVE" AND category=~"^SECURITY_HEALTH_ANALYTICS"',
        pageSize: 200,
      });
      const findings = r.data.listFindingsResults ?? [];
      shaCriticalCount = findings.filter((f: any) => f.finding?.severity === 'CRITICAL').length;
      shaHighCount = findings.filter((f: any) => f.finding?.severity === 'HIGH').length;
      evidence.push(ev('securitycenter.sha_findings', { critical: shaCriticalCount, high: shaHighCount, total_returned: findings.length }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.projects.findings.list', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.googleClient', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }

  try {
    const recommender = await gcpAuth.googleClient<any>('recommender', 'v1');
    const recommenderIds = ['google.iam.policy.Recommender', 'google.compute.firewall.Recommender'];
    for (const rid of recommenderIds) {
      try {
        const r = await recommender.projects.locations.recommenders.recommendations.list({
          parent: `projects/${ctx.project}/locations/global/recommenders/${rid}`,
          pageSize: 100,
        });
        recommendationsCount += r.data.recommendations?.length ?? 0;
      } catch { /* may not be enabled */ }
    }
    evidence.push(ev('recommender.security_recommendations', { count: recommendationsCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'recommender.recommendations.list', 'recommender.*.list (roles/recommender.viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.scc.no_critical_sha_findings',
      passed: shaCriticalCount === 0,
      severity: 'critical',
      current: {
        summary: `${shaCriticalCount} CRITICAL active Security Health Analytics finding(s).`,
        observations: { sha_critical: shaCriticalCount, sha_high: shaHighCount },
      },
      target: { summary: 'Zero unmuted active CRITICAL SHA findings.', rationale: 'NIST SI-4, RA-5.' },
      gap: shaCriticalCount === 0 ? undefined : {
        description: 'Critical posture findings open.',
        affected_resources: [{ type: 'google_scc_finding', identifier: 'aggregate', attributes: { count: shaCriticalCount } }],
      },
      remediation: shaCriticalCount === 0 ? undefined : {
        summary: 'Triage in SCC console.',
        options: [{
          approach: 'Open SCC console; close each finding.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Depends on remediation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per finding.' },
          steps: ['Sort by severity + age.', 'For each: remediate, mute with justification, or document.'],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party CSPM (Wiz, Lacework, Prisma Cloud)', description: 'CSPM can substitute.', evidence_required: ['CSPM posture export'], detected: false },
      ],
      nist_controls: ['si-4','ra-5'],
    }),

    finding({
      rule: 'gcp.recommender.security_recommendations_managed',
      passed: recommendationsCount <= 25,
      severity: 'medium',
      current: {
        summary: `${recommendationsCount} security recommendation(s) from Recommender.`,
        observations: { count: recommendationsCount },
      },
      target: { summary: 'Active security recommendations ≤ 25 and trending down.', rationale: 'Recommender catches policy + firewall over-grants.' },
      gap: recommendationsCount <= 25 ? undefined : {
        description: 'Recommendations accumulating; remediation backlog.',
        affected_resources: [{ type: 'google_recommender_recommendation', identifier: 'aggregate', attributes: { count: recommendationsCount } }],
      },
      remediation: recommendationsCount <= 25 ? undefined : {
        summary: 'Apply or dismiss each recommendation with justification.',
        options: [{
          approach: 'Bulk-triage via console / API.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Depends on recommendation.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Backlog burndown.' },
          steps: ['Export recommendations.', 'For each: apply / dismiss / defer.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-6','cm-7'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-ACM — Automating Configuration Management (GCP)
// =====================================================================
export async function collectSvcAcm(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Cloud Build triggers (proxy for IaC pipelines)
  let buildTriggerCount = 0;
  try {
    const cb = await gcpAuth.googleClient<any>('cloudbuild', 'v1');
    const r = await cb.projects.triggers.list({ projectId: ctx.project });
    buildTriggerCount = (r.data.triggers ?? []).length;
    evidence.push(ev('cloudbuild.trigger_count_for_acm', { count: buildTriggerCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudbuild.projects.triggers.list', 'cloudbuild.builds.list (roles/cloudbuild.builds.viewer)')); }

  // Asset Inventory feed count (drift detection signal)
  let feedCount = 0;
  try {
    const cloudasset = await gcpAuth.googleClient<any>('cloudasset', 'v1');
    const r = await cloudasset.feeds.list({ parent: `projects/${ctx.project}` });
    feedCount = r.data.feeds?.length ?? 0;
    evidence.push(ev('cloudasset.feeds_for_acm', { count: feedCount }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudasset.feeds.list', 'cloudasset.feeds.list (roles/cloudasset.viewer)')); }

  // Config Connector / Anthos Config Mgmt (already in CNA-EIS but tagged here for ACM)
  let policyControllerInstalled = false;
  try {
    const gkehub = await gcpAuth.googleClient<any>('gkehub', 'v1');
    const r = await gkehub.projects.locations.features.list({ parent: `projects/${ctx.project}/locations/global` });
    policyControllerInstalled = (r.data.resources ?? []).some((f: any) => /policycontroller|configmanagement/.test(f.name ?? ''));
    evidence.push(ev('gkehub.config_management', { installed: policyControllerInstalled }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'gkehub.projects.locations.features.list', 'gkehub.features.list (roles/gkehub.viewer)')); }

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Terraform Cloud / Atlantis / Spacelift',
      description: 'Off-GCP IaC tool of record.',
      evidence_required: ['TF workspace inventory', 'Apply timestamps', 'Drift-detection schedule'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.iac_pipeline_present',
      passed: buildTriggerCount >= 1 || policyControllerInstalled,
      severity: 'high',
      current: {
        summary: buildTriggerCount >= 1 || policyControllerInstalled
          ? `IaC automation present: ${buildTriggerCount} Cloud Build trigger(s), Config Mgmt: ${policyControllerInstalled}.`
          : 'No Cloud Build triggers and no Anthos Config Management — IaC may live entirely off-GCP.',
        observations: { build_triggers: buildTriggerCount, policy_controller: policyControllerInstalled, asset_feeds: feedCount },
      },
      target: { summary: 'Cloud Build / Config Connector / Anthos Config Management OR documented off-GCP IaC tool drives state.', rationale: 'NIST CM-2, CM-3, CM-6.' },
      gap: (buildTriggerCount >= 1 || policyControllerInstalled) ? undefined : {
        description: 'No detectable IaC automation.',
        affected_resources: [{ type: 'google_cloudbuild_trigger', identifier: 'aggregate', attributes: { count: 0 } }],
      },
      remediation: (buildTriggerCount >= 1 || policyControllerInstalled) ? undefined : {
        summary: 'Adopt Cloud Build / Config Connector OR document external IaC.',
        options: [{
          approach: 'Cloud Build + Terraform pipeline.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Cloud Build minutes.' },
          availability_impact: { level: 'low', notes: 'Net-new.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'months', notes: 'IaC import is long-term.' },
          steps: ['Set up Cloud Build trigger for `terraform plan` + `terraform apply`.', 'Migrate existing resources into TF state.', 'Establish review cadence.'],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['cm-2','cm-3','cm-6'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-EIS — Evaluating and Improving Security (GCP)
// =====================================================================
export async function collectSvcEis(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  let inactiveCount = 0;
  let activeCount = 0;
  try {
    const scc = await gcpAuth.googleClient<any>('securitycenter', 'v1');
    try {
      const r1 = await scc.projects.findings.list({ parent: `projects/${ctx.project}/sources/-`, filter: 'state="ACTIVE"', pageSize: 200 });
      activeCount = (r1.data.listFindingsResults ?? []).length;
      const r2 = await scc.projects.findings.list({ parent: `projects/${ctx.project}/sources/-`, filter: 'state="INACTIVE"', pageSize: 200 });
      inactiveCount = (r2.data.listFindingsResults ?? []).length;
      evidence.push(ev('securitycenter.lifecycle_for_eis', { active: activeCount, inactive: inactiveCount }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.projects.findings.list', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.googleClient', 'securitycenter.findings.list (roles/securitycenter.findingsViewer)')); }

  const total = activeCount + inactiveCount;
  const resolvedRatio = total > 0 ? inactiveCount / total : 0;

  const findings = [
    finding({
      rule: 'gcp.scc.improvement_loop_active',
      passed: total === 0 || resolvedRatio >= 0.3,
      severity: 'medium',
      current: {
        summary: total === 0
          ? 'No SCC findings to evaluate improvement loop on.'
          : `SCC: ${activeCount} ACTIVE, ${inactiveCount} INACTIVE (${Math.round(resolvedRatio*100)}% resolved).`,
        observations: { active: activeCount, inactive: inactiveCount, resolved_ratio: resolvedRatio },
      },
      target: { summary: '≥30% of findings reach INACTIVE state — the loop is closing.', rationale: 'NIST CA-7, PM-31.' },
      gap: (total === 0 || resolvedRatio >= 0.3) ? undefined : {
        description: 'Findings accumulate without remediation.',
        affected_resources: [{ type: 'google_scc_finding', identifier: 'aggregate', attributes: { active: activeCount, inactive: inactiveCount } }],
      },
      remediation: (total === 0 || resolvedRatio >= 0.3) ? undefined : {
        summary: 'Wire SCC → ticketing + improvement-decision log.',
        options: [{
          approach: 'SCC notification → Pub/Sub → ticketing.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'low', notes: 'Pub/Sub charges.' },
          availability_impact: { level: 'none', notes: 'Pure routing.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Integration + process change.' },
          steps: ['Create SCC notification config.', 'Cloud Function consumes Pub/Sub messages → creates tickets.', 'Log each resolved finding\'s decision.'],
        }],
      },
      alternative_satisfiers: [
        { via: 'External CSPM (Wiz, Lacework, Prisma)', description: 'External tool drives loop.', evidence_required: ['CSPM resolution audit log'], detected: false },
      ],
      nist_controls: ['ca-7','pm-31'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-EVC', relationship: 'shares-remediation', note: 'Same source data; different cadence vs outcome focus.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}
