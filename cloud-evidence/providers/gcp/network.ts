/**
 * GCP network-domain CNA collectors.
 * Covers: KSI-CNA-MAT, KSI-CNA-RNT, KSI-CNA-ULN, KSI-CNA-RVP.
 * All read-only (.get / .list / .getIamPolicy).
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, AlternativeSatisfier, ThirdPartyToolMatch } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { detect as detectThirdParty } from '../../core/detect/third-party-tools.ts';

const ADMIN_PORTS = ['22', '3389', '3306', '5432', '6379', '27017', '9200'];

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

interface Ctx { project: string; }
function setupCtx(c: CollectorContext): Ctx {
  if (!c.gcp?.project_id) throw new Error('GCP collector invoked without project_id');
  return { project: c.gcp.project_id };
}

interface NetworkInventory {
  firewalls: any[];
  instances: any[];
  networks: any[];
  subnetworks: any[];
  clusters: any[];
  buckets: any[];
  bucketsWithoutPublicAccessPrevention: string[];
  bucketsWithoutUniformAccess: string[];
  bucketsAllUsers: string[];
  sqlInstances: any[];
  cloudRunServices: any[];
  cloudArmorPolicies: any[];
  routers: any[];
  forwardingRules: any[];
}

async function fetchInventory(ctx: Ctx): Promise<{ inv: NetworkInventory; warnings: string[]; evidence: RawEvidence[] }> {
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const inv: NetworkInventory = {
    firewalls: [], instances: [], networks: [], subnetworks: [], clusters: [],
    buckets: [], bucketsWithoutPublicAccessPrevention: [], bucketsWithoutUniformAccess: [], bucketsAllUsers: [],
    sqlInstances: [], cloudRunServices: [], cloudArmorPolicies: [], routers: [], forwardingRules: [],
  };

  const compute = await gcpAuth.googleClient<any>('compute', 'v1');
  try {
    const r = await compute.firewalls.list({ project: ctx.project, maxResults: 500 });
    inv.firewalls = r.data.items ?? [];
    evidence.push(ev('compute.firewalls.list', { count: inv.firewalls.length }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.firewalls.list', 'compute.firewalls.list (roles/compute.viewer)')); }

  try {
    const r = await compute.instances.aggregatedList({ project: ctx.project });
    const items = r.data.items ?? {};
    for (const zone of Object.values<any>(items)) {
      inv.instances.push(...(zone.instances ?? []));
    }
    evidence.push(ev('compute.instances.aggregatedList', { count: inv.instances.length }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.instances.aggregatedList', 'compute.instances.list (roles/compute.viewer)')); }

  try {
    const r = await compute.networks.list({ project: ctx.project });
    inv.networks = r.data.items ?? [];
    evidence.push(ev('compute.networks.list', { count: inv.networks.length }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.networks.list', 'compute.networks.list (roles/compute.viewer)')); }

  try {
    const r = await compute.subnetworks.aggregatedList({ project: ctx.project });
    const items = r.data.items ?? {};
    for (const region of Object.values<any>(items)) {
      inv.subnetworks.push(...(region.subnetworks ?? []));
    }
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.subnetworks.aggregatedList', 'compute.subnetworks.list (roles/compute.viewer)')); }

  try {
    const container = await gcpAuth.googleClient<any>('container', 'v1');
    const r = await container.projects.locations.clusters.list({ parent: `projects/${ctx.project}/locations/-` });
    inv.clusters = r.data.clusters ?? [];
    evidence.push(ev('container.clusters.list', inv.clusters.map((c: any) => ({
      name: c.name,
      privateNodes: c.privateClusterConfig?.enablePrivateNodes,
      privateEndpoint: c.privateClusterConfig?.enablePrivateEndpoint,
      networkPolicy: c.networkPolicy?.enabled,
      workloadIdentity: !!c.workloadIdentityConfig?.workloadPool,
      shieldedNodes: c.shieldedNodes?.enabled,
    }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'container.clusters.list', 'container.clusters.list (roles/container.viewer)')); }

  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const r = await storage.buckets.list({ project: ctx.project });
    inv.buckets = r.data.items ?? [];
    for (const b of inv.buckets) {
      if (b.iamConfiguration?.publicAccessPrevention !== 'enforced') inv.bucketsWithoutPublicAccessPrevention.push(b.name);
      if (!b.iamConfiguration?.uniformBucketLevelAccess?.enabled) inv.bucketsWithoutUniformAccess.push(b.name);
      try {
        const pol = await storage.buckets.getIamPolicy({ bucket: b.name });
        for (const binding of pol.data.bindings ?? []) {
          for (const m of binding.members ?? []) {
            if (m === 'allUsers' || m === 'allAuthenticatedUsers') inv.bucketsAllUsers.push(`${b.name}: ${binding.role} = ${m}`);
          }
        }
      } catch { /* ignore */ }
    }
    evidence.push(ev('storage.bucket_audit', { total: inv.buckets.length, without_pap: inv.bucketsWithoutPublicAccessPrevention, public_bindings: inv.bucketsAllUsers }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    inv.sqlInstances = r.data.items ?? [];
    evidence.push(ev('sqladmin.instances.list', inv.sqlInstances.map((i: any) => ({
      name: i.name, ipv4Enabled: i.settings?.ipConfiguration?.ipv4Enabled, authorizedNetworks: i.settings?.ipConfiguration?.authorizedNetworks,
    }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  try {
    const run = await gcpAuth.googleClient<any>('run', 'v1');
    const r = await run.namespaces.services.list({ parent: `namespaces/${ctx.project}` });
    inv.cloudRunServices = r.data.items ?? [];
    evidence.push(ev('run.services.list', inv.cloudRunServices.map((s: any) => ({
      name: s.metadata?.name,
      ingress: s.metadata?.annotations?.['run.googleapis.com/ingress'],
    }))));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'run.services.list', 'run.services.list (roles/run.viewer)')); }

  try {
    const r = await compute.securityPolicies.list({ project: ctx.project });
    inv.cloudArmorPolicies = r.data.items ?? [];
    evidence.push(ev('compute.securityPolicies.list', { count: inv.cloudArmorPolicies.length }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.securityPolicies.list', 'compute.securityPolicies.list (roles/compute.viewer)')); }

  try {
    const r = await compute.routers.aggregatedList({ project: ctx.project });
    const items = r.data.items ?? {};
    for (const region of Object.values<any>(items)) inv.routers.push(...(region.routers ?? []));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.routers.aggregatedList', 'compute.routers.list (roles/compute.viewer)')); }

  try {
    const r = await compute.forwardingRules.aggregatedList({ project: ctx.project });
    const items = r.data.items ?? {};
    for (const region of Object.values<any>(items)) inv.forwardingRules.push(...(region.forwardingRules ?? []));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.forwardingRules.aggregatedList', 'compute.forwardingRules.list (roles/compute.viewer)')); }

  return { inv, warnings, evidence };
}

// =====================================================================
// KSI-CNA-MAT — Minimizing Attack Surface
// =====================================================================
export async function collectCnaMat(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchInventory(ctx);

  const firewallsOpenToWorldAdmin: any[] = [];
  for (const fw of inv.firewalls) {
    if (fw.direction !== 'INGRESS' || fw.disabled) continue;
    if (!(fw.sourceRanges ?? []).includes('0.0.0.0/0')) continue;
    for (const allow of fw.allowed ?? []) {
      if (allow.IPProtocol === 'tcp' || allow.IPProtocol === 'udp' || allow.IPProtocol === 'all') {
        const ports = allow.ports ?? ['0-65535'];
        for (const p of ports) {
          if (ADMIN_PORTS.some((ap) => p === ap || (p.includes('-') && parseInt(p.split('-')[0]!, 10) <= parseInt(ap, 10) && parseInt(p.split('-')[1]!, 10) >= parseInt(ap, 10)))) {
            firewallsOpenToWorldAdmin.push({ name: fw.name, network: fw.network, port: p, protocol: allow.IPProtocol });
          }
        }
      }
    }
  }

  const instancesWithoutShieldedVm = inv.instances.filter((i: any) =>
    !(i.shieldedInstanceConfig?.enableSecureBoot && i.shieldedInstanceConfig?.enableVtpm && i.shieldedInstanceConfig?.enableIntegrityMonitoring)
  ).map((i: any) => i.name);

  const instancesWithPublicIp = inv.instances.filter((i: any) =>
    (i.networkInterfaces ?? []).some((nic: any) => (nic.accessConfigs ?? []).length > 0)
  ).map((i: any) => i.name);

  const sqlPublic = inv.sqlInstances.filter((i: any) => i.settings?.ipConfiguration?.ipv4Enabled === true).map((i: any) => i.name);

  const gkePublicEndpoint = inv.clusters.filter((c: any) => !c.privateClusterConfig?.enablePrivateEndpoint);

  const cloudRunUnauth = inv.cloudRunServices.filter((s: any) => {
    const ing = s.metadata?.annotations?.['run.googleapis.com/ingress'];
    return ing !== 'internal' && ing !== 'internal-and-cloud-load-balancing';
  }).map((s: any) => s.metadata?.name);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External CNAPP / CSPM (Wiz, Lacework, Prisma Cloud)',
      description: 'A CSPM/CNAPP tool may track attack-surface signals continuously.',
      evidence_required: ['CSPM tool tenant', 'Recent attack-surface report', 'Sample finding lifecycle'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings = [
    finding({
      rule: 'gcp.firewall.no_world_open_to_admin_ports',
      passed: firewallsOpenToWorldAdmin.length === 0,
      severity: 'critical',
      current: {
        summary: firewallsOpenToWorldAdmin.length === 0
          ? `No firewall rule allows 0.0.0.0/0 to admin ports across ${inv.firewalls.length} rules.`
          : `${firewallsOpenToWorldAdmin.length} firewall rule(s) allow 0.0.0.0/0 to administrative ports.`,
        observations: { violations: firewallsOpenToWorldAdmin, total_firewall_rules: inv.firewalls.length },
      },
      target: { summary: 'No firewall rule allows 0.0.0.0/0 to admin ports.', rationale: 'NIST SC-7. World-open admin ports = exploit target.' },
      gap: firewallsOpenToWorldAdmin.length === 0 ? undefined : {
        description: 'Each rule exposes a sensitive port.',
        affected_resources: firewallsOpenToWorldAdmin.map<AffectedResource>((f) => ({
          type: 'google_compute_firewall', identifier: f.name, name: f.name,
          attributes: { network: f.network, port: f.port, protocol: f.protocol },
        })),
      },
      remediation: firewallsOpenToWorldAdmin.length === 0 ? undefined : {
        summary: 'Remove world-open admin rules; use IAP TCP forwarding for shell access.',
        options: [{
          approach: 'Remove world-open firewall rule + adopt IAP for SSH/RDP.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'IAP TCP forwarding is free.' },
          availability_impact: { level: 'medium', notes: 'Operators must use `gcloud compute ssh --tunnel-through-iap`. Coordinate.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per rule + alternative-access setup.' },
          steps: [
            'For each violating firewall rule, audit who needs access.',
            'Set up IAP TCP forwarding allow rules (35.235.240.0/20 → port 22/3389).',
            'Grant roles/iap.tunnelResourceAccessor to operators.',
            'Remove the 0.0.0.0/0 rule via Terraform.',
            'Validate operators can SSH via IAP tunnel.',
          ],
          example_code: `# Replace world-open SSH rule with IAP-only:
resource "google_compute_firewall" "iap_ssh" {
  name    = "allow-iap-ssh"
  network = google_compute_network.this.name
  source_ranges = ["35.235.240.0/20"]   # IAP source range
  allow { protocol = "tcp"  ports = ["22"] }
}`,
          references: [{ title: 'IAP TCP forwarding', url: 'https://cloud.google.com/iap/docs/using-tcp-forwarding' }],
        }],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['sc-7','sc-7.5','ac-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-CNA-RNT', relationship: 'shares-remediation', note: 'Firewall hygiene also restricts traffic.' },
        { ksi_id: 'KSI-IAM-JIT', relationship: 'shares-remediation', note: 'IAP is the GCP JIT shell-access primitive.' },
      ],
    }),

    finding({
      rule: 'gcp.compute.shielded_vm_enabled',
      passed: instancesWithoutShieldedVm.length === 0,
      severity: 'high',
      current: {
        summary: instancesWithoutShieldedVm.length === 0
          ? `All ${inv.instances.length} instances have Shielded VM enabled.`
          : `${instancesWithoutShieldedVm.length} of ${inv.instances.length} instances lack Shielded VM (secureBoot/vTPM/integrityMonitoring).`,
        observations: { without_shielded_vm: instancesWithoutShieldedVm },
      },
      target: { summary: 'All in-scope VMs have Shielded VM (secureBoot + vTPM + integrityMonitoring).', rationale: 'NIST SI-7. Boot integrity defends against rootkits and kernel tampering.' },
      gap: instancesWithoutShieldedVm.length === 0 ? undefined : {
        description: 'Instances without Shielded VM lack hardware-rooted boot integrity.',
        affected_resources: instancesWithoutShieldedVm.map<AffectedResource>((n: string) => ({
          type: 'google_compute_instance', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: instancesWithoutShieldedVm.length === 0 ? undefined : {
        summary: 'Enable Shielded VM via instance config (requires stop/start for some changes).',
        options: [{
          approach: 'Set shielded_instance_config via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'No charge.' },
          availability_impact: { level: 'medium', notes: 'Some settings require instance stop/start.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per instance / template.' },
          steps: ['Update instance templates / individual instances.', 'Validate boot.', 'Roll forward.'],
          example_code: `resource "google_compute_instance" "app" {
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['si-7','si-7.1'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-SVC-VRI', relationship: 'shares-remediation', note: 'Shielded VM is resource-integrity evidence.' },
      ],
    }),

    finding({
      rule: 'gcp.storage.public_access_prevention_enforced',
      passed: inv.bucketsWithoutPublicAccessPrevention.length === 0,
      severity: 'critical',
      current: {
        summary: inv.bucketsWithoutPublicAccessPrevention.length === 0
          ? `All ${inv.buckets.length} bucket(s) have publicAccessPrevention=enforced.`
          : `${inv.bucketsWithoutPublicAccessPrevention.length} of ${inv.buckets.length} bucket(s) do NOT enforce publicAccessPrevention.`,
        observations: { total: inv.buckets.length, without_pap: inv.bucketsWithoutPublicAccessPrevention, public_bindings: inv.bucketsAllUsers },
      },
      target: { summary: 'Every bucket has iamConfiguration.publicAccessPrevention=enforced + uniformBucketLevelAccess=true. No allUsers / allAuthenticatedUsers bindings.', rationale: 'NIST AC-3, SC-7. Public buckets = breach risk.' },
      gap: inv.bucketsWithoutPublicAccessPrevention.length === 0 ? undefined : {
        description: 'Buckets without enforced publicAccessPrevention can be made public via IAM mistake.',
        affected_resources: inv.bucketsWithoutPublicAccessPrevention.map<AffectedResource>((name) => ({
          type: 'google_storage_bucket', identifier: name, name, attributes: {},
        })),
      },
      remediation: inv.bucketsWithoutPublicAccessPrevention.length === 0 ? undefined : {
        summary: 'Set publicAccessPrevention=enforced + uniformBucketLevelAccess=true on every bucket; enforce org policy.',
        options: [{
          approach: 'Enforce via org policy + per-bucket Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'high', notes: 'If any bucket is INTENTIONALLY public (rare), this breaks it.' },
          customer_visible: { level: 'medium', notes: 'Public-asset buckets need to move to CDN-fronted pattern.' },
          effort_estimate: { magnitude: 'days', notes: 'Audit intent of each public bucket first.' },
          steps: ['Audit each bucket\'s intent.', 'Enforce org policy constraint storage.publicAccessPrevention.', 'Update buckets via Terraform.'],
          example_code: `resource "google_storage_bucket" "data" {
  name     = "your-data-bucket"
  location = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}
resource "google_org_policy_policy" "pap" {
  name   = "organizations/$\${var.org_id}/policies/storage.publicAccessPrevention"
  parent = "organizations/$\${var.org_id}"
  spec { rules { enforce = "TRUE" } }
}`,
          references: [{ title: 'GCS publicAccessPrevention', url: 'https://cloud.google.com/storage/docs/public-access-prevention' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','sc-7'],
    }),

    finding({
      rule: 'gcp.cloudsql.no_public_ip',
      passed: sqlPublic.length === 0,
      severity: 'high',
      current: {
        summary: sqlPublic.length === 0
          ? `No Cloud SQL instances have public IPv4 among ${inv.sqlInstances.length} total.`
          : `${sqlPublic.length} Cloud SQL instance(s) have ipv4Enabled=true.`,
        observations: { violations: sqlPublic },
      },
      target: { summary: 'No prod Cloud SQL instance has ipv4Enabled=true.', rationale: 'NIST SC-7. Use private IP + Private Service Connect or VPC peering.' },
      gap: sqlPublic.length === 0 ? undefined : {
        description: 'Public Cloud SQL is internet-exposed.',
        affected_resources: sqlPublic.map<AffectedResource>((n: string) => ({ type: 'google_sql_database_instance', identifier: n, name: n, attributes: {} })),
      },
      remediation: sqlPublic.length === 0 ? undefined : {
        summary: 'Migrate to private IP via Terraform; use PSC for external consumers.',
        options: [{
          approach: 'Set ipv4_enabled=false; configure private_network.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'Private Service Connect for cross-VPC consumers has small per-endpoint cost.' },
          availability_impact: { level: 'medium', notes: 'External clients via public IP must move to private connectivity.' },
          customer_visible: { level: 'low', notes: 'Affects only external integrations.' },
          effort_estimate: { magnitude: 'days', notes: 'Per instance.' },
          steps: ['Reserve private services access range.', 'Update settings.ip_configuration.', 'Migrate consumers.'],
          example_code: `resource "google_sql_database_instance" "main" {
  settings {
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.this.id
    }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7'],
    }),

    finding({
      rule: 'gcp.gke.private_endpoint',
      passed: gkePublicEndpoint.length === 0,
      severity: 'high',
      current: {
        summary: gkePublicEndpoint.length === 0
          ? `All ${inv.clusters.length} GKE cluster(s) have private endpoints.`
          : `${gkePublicEndpoint.length} GKE cluster(s) have public endpoints enabled.`,
        observations: { clusters_public_endpoint: gkePublicEndpoint.map((c: any) => ({ name: c.name, masterAuthorizedNetworks: c.masterAuthorizedNetworksConfig })) },
      },
      target: { summary: 'GKE private endpoint enabled OR master authorized networks restricted to a tight CIDR allowlist.', rationale: 'NIST SC-7. Public K8s API = RCE surface.' },
      gap: gkePublicEndpoint.length === 0 ? undefined : {
        description: 'Public K8s API endpoint.',
        affected_resources: gkePublicEndpoint.map<AffectedResource>((c: any) => ({
          type: 'google_container_cluster', identifier: c.name, name: c.name,
          attributes: { masterAuthorizedNetworks: c.masterAuthorizedNetworksConfig },
        })),
      },
      remediation: gkePublicEndpoint.length === 0 ? undefined : {
        summary: 'Enable private endpoint; expose API only via authorized networks.',
        options: [{
          approach: 'Update GKE cluster to private endpoint + master_authorized_networks_config.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Existing kubectl users from arbitrary IPs lose access.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Per cluster.' },
          steps: ['Update private_cluster_config.', 'Add master authorized networks.', 'Apply via canary cluster first.'],
          example_code: `resource "google_container_cluster" "this" {
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
  master_authorized_networks_config {
    cidr_blocks { display_name = "corp-vpn" cidr_block = "203.0.113.0/24" }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','ac-3'],
    }),

    finding({
      rule: 'gcp.cloud_run.no_unauth_invocation',
      passed: cloudRunUnauth.length === 0,
      severity: 'high',
      current: {
        summary: cloudRunUnauth.length === 0
          ? `All ${inv.cloudRunServices.length} Cloud Run service(s) restrict ingress to internal.`
          : `${cloudRunUnauth.length} Cloud Run service(s) accept public ingress.`,
        observations: { unrestricted_services: cloudRunUnauth },
      },
      target: { summary: 'Cloud Run prod services have ingress=internal or internal-and-cloud-load-balancing AND require auth (no allUsers IAM binding).', rationale: 'NIST AC-3.' },
      gap: cloudRunUnauth.length === 0 ? undefined : {
        description: 'Public Cloud Run services are world-callable.',
        affected_resources: cloudRunUnauth.map<AffectedResource>((n: string) => ({ type: 'google_cloud_run_service', identifier: n, name: n, attributes: {} })),
      },
      remediation: cloudRunUnauth.length === 0 ? undefined : {
        summary: 'Restrict ingress + remove allUsers bindings; front public services with a load balancer + IAP/Cloud Armor.',
        options: [{
          approach: 'Set ingress=internal-and-cloud-load-balancing; require auth.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'low', notes: 'External Application Load Balancer has cost.' },
          availability_impact: { level: 'medium', notes: 'Public consumers must move to LB endpoint with auth.' },
          customer_visible: { level: 'medium', notes: 'If customer-facing API, customers need updated endpoint.' },
          effort_estimate: { magnitude: 'days', notes: 'Per service.' },
          steps: ['Set ingress annotation.', 'Remove allUsers IAM binding.', 'Front with HTTPS LB + Cloud Armor.'],
          example_code: `resource "google_cloud_run_service" "api" {
  metadata {
    annotations = { "run.googleapis.com/ingress" = "internal-and-cloud-load-balancing" }
  }
}`,
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-3','sc-7'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-RNT — Restricting Network Traffic
// =====================================================================
export async function collectCnaRnt(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchInventory(ctx);

  const subnetsWithoutFlowLogs = inv.subnetworks.filter((s: any) => s.logConfig?.enable !== true).map((s: any) => s.name);
  const gkeWithoutNetworkPolicy = inv.clusters.filter((c: any) => !c.networkPolicy?.enabled).map((c: any) => c.name);

  const findings = [
    finding({
      rule: 'gcp.vpc_flow_logs_enabled_all_subnets',
      passed: subnetsWithoutFlowLogs.length === 0,
      severity: 'high',
      current: {
        summary: subnetsWithoutFlowLogs.length === 0
          ? `All ${inv.subnetworks.length} subnets have flow logs enabled.`
          : `${subnetsWithoutFlowLogs.length} of ${inv.subnetworks.length} subnets do NOT have flow logs.`,
        observations: { subnets_without_flow_logs: subnetsWithoutFlowLogs },
      },
      target: { summary: 'Every prod subnet has logConfig.enable=true.', rationale: 'NIST AU-2, SI-4. Flow logs are foundational forensics.' },
      gap: subnetsWithoutFlowLogs.length === 0 ? undefined : {
        description: 'Subnet-level traffic visibility is absent.',
        affected_resources: subnetsWithoutFlowLogs.map<AffectedResource>((n: string) => ({
          type: 'google_compute_subnetwork', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: subnetsWithoutFlowLogs.length === 0 ? undefined : {
        summary: 'Enable flow logs on each subnet.',
        options: [{
          approach: 'Set log_config on each subnetwork via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Logs are charged by ingest GB.' },
          availability_impact: { level: 'none', notes: 'Pure logging.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Update subnetwork log_config.', 'Verify logs in Cloud Logging.'],
          example_code: `resource "google_compute_subnetwork" "private" {
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}`,
          references: [{ title: 'VPC Flow Logs', url: 'https://cloud.google.com/vpc/docs/flow-logs' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['au-2','si-4'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-MLA-LET', relationship: 'shares-remediation', note: 'Flow logs are part of the logged-event-type inventory.' },
      ],
    }),

    finding({
      rule: 'gcp.gke.network_policy_enabled',
      passed: gkeWithoutNetworkPolicy.length === 0,
      severity: 'high',
      current: {
        summary: gkeWithoutNetworkPolicy.length === 0
          ? `All ${inv.clusters.length} GKE cluster(s) have NetworkPolicy enabled.`
          : `${gkeWithoutNetworkPolicy.length} GKE cluster(s) lack NetworkPolicy.`,
        observations: { clusters_without_network_policy: gkeWithoutNetworkPolicy },
      },
      target: { summary: 'Every prod GKE cluster has networkPolicy.enabled=true (Calico or Cilium).', rationale: 'NIST AC-4. Without K8s NetworkPolicy, pod-to-pod traffic is unrestricted.' },
      gap: gkeWithoutNetworkPolicy.length === 0 ? undefined : {
        description: 'Pods can reach any other pod by default — lateral-movement risk.',
        affected_resources: gkeWithoutNetworkPolicy.map<AffectedResource>((n: string) => ({
          type: 'google_container_cluster', identifier: n, name: n, attributes: {},
        })),
      },
      remediation: gkeWithoutNetworkPolicy.length === 0 ? undefined : {
        summary: 'Enable NetworkPolicy on each cluster + author NetworkPolicy manifests per namespace.',
        options: [{
          approach: 'Enable NetworkPolicy via Terraform; deploy default-deny NetworkPolicy per namespace.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Default-deny NetworkPolicy will break ingress/egress without explicit allow rules.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Cluster enablement is quick; per-namespace policy authoring takes time.' },
          steps: ['Enable on cluster (requires node-pool restart for Calico).', 'Deploy default-deny NetworkPolicy.', 'Add allow-rules incrementally.'],
          example_code: `resource "google_container_cluster" "this" {
  network_policy { enabled = true }
  addons_config { network_policy_config { disabled = false } }
}`,
          references: [{ title: 'GKE Network Policy', url: 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ac-4','sc-7'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-ULN — Using Logical Networking
// =====================================================================
export async function collectCnaUln(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchInventory(ctx);

  const findings = [
    finding({
      rule: 'gcp.vpc.logical_separation',
      passed: inv.networks.length >= 1,
      severity: 'medium',
      current: {
        summary: `${inv.networks.length} VPC network(s) in project ${ctx.project}.`,
        observations: {
          networks: inv.networks.map((n: any) => ({ name: n.name, subnets: n.subnetworks?.length })),
          subnetworks: inv.subnetworks.length,
        },
      },
      target: { summary: 'Prod is in a separate VPC/project from nonprod. Documented inter-project Shared VPC / VPC peering / Service Project model.', rationale: 'NIST SC-32 (system partitioning).' },
      gap: inv.networks.length >= 1 ? undefined : {
        description: 'No VPC networks found in this project — verify project scope or provision a network.',
        affected_resources: [],
      },
      remediation: inv.networks.length >= 1 ? undefined : {
        summary: 'Confirm project scope or provision the baseline VPC network.',
        options: [{
          approach: 'Create a custom-mode VPC network with per-region subnets via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          steps: ['Confirm the project ID is the right one.', 'If by design empty, document as inherited.', 'Otherwise create google_compute_network + subnets.'],
          cost_impact: { level: 'none', notes: 'Networks are free; cross-region egress is metered.' },
          availability_impact: { level: 'low', notes: 'Net-new infra.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'For baseline VPC.' },
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-7','sc-32'],
    }),

    finding({
      rule: 'gcp.gke.workload_identity_enabled',
      passed: inv.clusters.every((c: any) => !!c.workloadIdentityConfig?.workloadPool),
      severity: 'high',
      current: {
        summary: inv.clusters.every((c: any) => !!c.workloadIdentityConfig?.workloadPool)
          ? `All ${inv.clusters.length} GKE cluster(s) have Workload Identity.`
          : `${inv.clusters.filter((c: any) => !c.workloadIdentityConfig?.workloadPool).length} cluster(s) lack Workload Identity.`,
        observations: { clusters: inv.clusters.map((c: any) => ({ name: c.name, workloadIdentity: !!c.workloadIdentityConfig?.workloadPool })) },
      },
      target: { summary: 'All prod GKE clusters have workloadIdentityConfig.workloadPool set.', rationale: 'Workload Identity replaces static SA keys with short-lived tokens — NIST IA-5.' },
      gap: inv.clusters.every((c: any) => !!c.workloadIdentityConfig?.workloadPool) ? undefined : {
        description: 'Pods without Workload Identity authenticate via node-attached SAs (broader privileges).',
        affected_resources: inv.clusters.filter((c: any) => !c.workloadIdentityConfig?.workloadPool).map<AffectedResource>((c: any) => ({
          type: 'google_container_cluster', identifier: c.name, name: c.name, attributes: {},
        })),
      },
      remediation: inv.clusters.every((c: any) => !!c.workloadIdentityConfig?.workloadPool) ? undefined : {
        summary: 'Enable Workload Identity on each cluster.',
        options: [{
          approach: 'Enable Workload Identity via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Per-namespace migration to use K8s SAs bound to GCP SAs.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'days', notes: 'Cluster setup + per-namespace migration.' },
          steps: ['Enable workload_identity_config on cluster.', 'Annotate K8s SAs with GCP SA email.', 'Bind via roles/iam.workloadIdentityUser.'],
          example_code: `resource "google_container_cluster" "this" {
  workload_identity_config {
    workload_pool = "$\${var.project_id}.svc.id.goog"
  }
}`,
          references: [{ title: 'GKE Workload Identity', url: 'https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ia-5','ia-9'],
      cross_ksi_dependencies: [
        { ksi_id: 'KSI-IAM-SNU', relationship: 'shares-remediation', note: 'Workload Identity directly serves non-user auth.' },
      ],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-CNA-RVP — Reviewing Protections (DoS)
// =====================================================================
export async function collectCnaRvp(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const { inv, warnings, evidence } = await fetchInventory(ctx);

  const armorWithRateRules: string[] = [];
  for (const p of inv.cloudArmorPolicies) {
    const hasRate = (p.rules ?? []).some((r: any) => r.rateLimitOptions);
    if (hasRate) armorWithRateRules.push(p.name);
  }

  const findings = [
    finding({
      rule: 'gcp.cloud_armor.rate_based_protection_present',
      passed: armorWithRateRules.length >= 1,
      severity: 'high',
      current: {
        summary: armorWithRateRules.length >= 1
          ? `${armorWithRateRules.length} Cloud Armor policy/policies with rate-based rules.`
          : `Cloud Armor policies: ${inv.cloudArmorPolicies.length}; rate-based rules: 0.`,
        observations: { total_policies: inv.cloudArmorPolicies.length, with_rate_rules: armorWithRateRules },
      },
      target: { summary: 'Every internet-facing HTTPS LB has a Cloud Armor policy with rate-based rules + Adaptive Protection enabled.', rationale: 'NIST SC-5. FedRAMP 20x requires DoS protection review.' },
      gap: armorWithRateRules.length >= 1 ? undefined : {
        description: 'No rate-based protection — public endpoints are vulnerable to volumetric L7 attacks.',
        affected_resources: [{ type: 'google_compute_security_policy', identifier: 'none-with-rate-rules', attributes: {} }],
      },
      remediation: armorWithRateRules.length >= 1 ? undefined : {
        summary: 'Create Cloud Armor security policy with rate-limit rule + Adaptive Protection; attach to HTTPS LBs.',
        options: [{
          approach: 'Cloud Armor with rate-limit + Adaptive Protection via Terraform.',
          mechanism: 'terraform',
          owner_team: 'Security',
          cost_impact: { level: 'medium', notes: 'Cloud Armor Standard is free for the policy; Adaptive Protection requires Cloud Armor Enterprise.' },
          availability_impact: { level: 'low', notes: 'Use PREVIEW mode first.' },
          customer_visible: { level: 'low', notes: 'Legitimate users may rarely see 429.' },
          effort_estimate: { magnitude: 'weeks', notes: 'Setup + tuning.' },
          steps: ['Create security policy with rate_limit_options.', 'Attach to backend service of HTTPS LB.', 'PREVIEW mode 2 weeks; promote to enforce.'],
          example_code: `resource "google_compute_security_policy" "main" {
  name = "main"
  adaptive_protection_config { layer_7_ddos_defense_config { enable = true } }
  rule {
    action   = "rate_based_ban"
    priority = 1000
    match { versioned_expr = "SRC_IPS_V1" config { src_ip_ranges = ["*"] } }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold { count = 2000 interval_sec = 60 }
    }
  }
  rule { action = "allow"  priority = 2147483647  match { versioned_expr = "SRC_IPS_V1" config { src_ip_ranges = ["*"] } } }
}`,
          references: [{ title: 'Cloud Armor', url: 'https://cloud.google.com/armor/docs' }],
        }],
      },
      alternative_satisfiers: [
        { via: '3rd-party CDN with DoS (Cloudflare, Akamai, Fastly)', description: 'CDN-fronted endpoints with built-in DoS protection.', evidence_required: ['CDN WAF config', 'recent traffic chart'], detected: false },
      ],
      nist_controls: ['sc-5','sc-5.1','sc-5.2'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}

// =====================================================================
// KSI-SVC-SNT — Securing Network Traffic (GCP)
// =====================================================================
export async function collectSvcSnt(c: CollectorContext): Promise<ProviderBlock> {
  const ctx = setupCtx(c);
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];

  // Target HTTPS proxies + their SSL policies
  interface HttpsProxyAudit { name: string; sslPolicy?: string; }
  const httpsProxies: HttpsProxyAudit[] = [];
  const sslPolicies: Record<string, any> = {};
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    const proxies = await compute.targetHttpsProxies.list({ project: ctx.project });
    for (const p of proxies.data.items ?? []) {
      httpsProxies.push({ name: p.name, sslPolicy: p.sslPolicy });
    }
    evidence.push(ev('compute.targetHttpsProxies', httpsProxies));

    const policies = await compute.sslPolicies.list({ project: ctx.project });
    for (const sp of policies.data.items ?? []) {
      sslPolicies[sp.name] = {
        minTlsVersion: sp.minTlsVersion,
        profile: sp.profile,
        customFeatures: sp.customFeatures,
      };
    }
    evidence.push(ev('compute.sslPolicies', sslPolicies));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.targetHttpsProxies.list/sslPolicies.list', 'compute.sslPolicies.list (roles/compute.viewer)')); }

  // Proxies WITHOUT an explicit ssl_policy use GCP-COMPATIBLE default which allows TLS 1.0
  const proxiesWithoutSslPolicy = httpsProxies.filter((p) => !p.sslPolicy);

  // Proxies WITH a weak SSL policy (TLS_1_0 or TLS_1_1 in minTlsVersion)
  const proxiesWithWeakPolicy = httpsProxies.filter((p) => {
    if (!p.sslPolicy) return false;
    const polName = p.sslPolicy.split('/').pop() ?? '';
    const pol = sslPolicies[polName];
    if (!pol) return false;
    return pol.minTlsVersion === 'TLS_1_0' || pol.minTlsVersion === 'TLS_1_1';
  });

  // Cloud SQL — requireSsl
  const sqlWithoutRequireSsl: string[] = [];
  let sqlCount = 0;
  try {
    const sqladmin = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sqladmin.instances.list({ project: ctx.project });
    for (const i of r.data.items ?? []) {
      sqlCount++;
      if (!i.settings?.ipConfiguration?.requireSsl) sqlWithoutRequireSsl.push(i.name);
    }
    evidence.push(ev('sqladmin.require_ssl', { total: sqlCount, without_require_ssl: sqlWithoutRequireSsl }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  const findings = [
    finding({
      rule: 'gcp.lb.ssl_policy_attached',
      passed: proxiesWithoutSslPolicy.length === 0,
      severity: 'high',
      current: {
        summary: proxiesWithoutSslPolicy.length === 0
          ? `All ${httpsProxies.length} HTTPS proxy/proxies have an explicit SSL policy.`
          : `${proxiesWithoutSslPolicy.length} of ${httpsProxies.length} HTTPS proxy/proxies use the default SSL policy (GCP-COMPATIBLE — allows TLS 1.0/1.1).`,
        observations: { without_ssl_policy: proxiesWithoutSslPolicy, all_policies: sslPolicies },
      },
      target: { summary: 'Every prod HTTPS LB has an explicit SSL policy with minTlsVersion=TLS_1_2 and profile=RESTRICTED or MODERN.', rationale: 'NIST SC-8.1. Default policy is too permissive.' },
      gap: proxiesWithoutSslPolicy.length === 0 ? undefined : {
        description: 'Default SSL policy allows TLS 1.0/1.1 — downgrade attack surface.',
        affected_resources: proxiesWithoutSslPolicy.map<AffectedResource>((p) => ({
          type: 'google_compute_target_https_proxy', identifier: p.name, name: p.name, attributes: { ssl_policy: 'default' },
        })),
      },
      remediation: proxiesWithoutSslPolicy.length === 0 ? undefined : {
        summary: 'Create restricted SSL policy + attach to each HTTPS proxy.',
        options: [{
          approach: 'Apply SSL policy via Terraform.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Very old clients (TLS 1.0/1.1) lose access.' },
          customer_visible: { level: 'low', notes: 'Old browsers/curl versions fail handshake.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Create google_compute_ssl_policy (profile=RESTRICTED, min_tls_version=TLS_1_2).', 'Reference in target_https_proxy ssl_policy.', 'Apply.'],
          example_code: 'resource "google_compute_ssl_policy" "restricted" {\n  name            = "restricted"\n  profile         = "RESTRICTED"\n  min_tls_version = "TLS_1_2"\n}\nresource "google_compute_target_https_proxy" "main" {\n  ssl_policy = google_compute_ssl_policy.restricted.id\n}',
          references: [{ title: 'SSL policies', url: 'https://cloud.google.com/load-balancing/docs/ssl-policies-concepts' }],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8','sc-8.1'],
    }),

    finding({
      rule: 'gcp.lb.no_weak_tls_policy',
      passed: proxiesWithWeakPolicy.length === 0,
      severity: 'high',
      current: {
        summary: proxiesWithWeakPolicy.length === 0
          ? 'No HTTPS proxy uses an SSL policy with minTlsVersion < 1.2.'
          : `${proxiesWithWeakPolicy.length} proxy/proxies use a weak SSL policy.`,
        observations: { weak_proxies: proxiesWithWeakPolicy },
      },
      target: { summary: 'SSL policies minTlsVersion=TLS_1_2 (or TLS_1_3).', rationale: 'NIST SC-8.1.' },
      gap: proxiesWithWeakPolicy.length === 0 ? undefined : {
        description: 'TLS 1.0/1.1 still accepted.',
        affected_resources: proxiesWithWeakPolicy.map<AffectedResource>((p) => ({
          type: 'google_compute_target_https_proxy', identifier: p.name, name: p.name, attributes: { ssl_policy: p.sslPolicy },
        })),
      },
      remediation: proxiesWithWeakPolicy.length === 0 ? undefined : {
        summary: 'Update SSL policy min_tls_version.',
        options: [{
          approach: 'Update SSL policy.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'low', notes: 'Old clients fail.' },
          customer_visible: { level: 'low', notes: 'Old browsers fail.' },
          effort_estimate: { magnitude: 'hours', notes: 'Apply Terraform.' },
          steps: ['Set min_tls_version=TLS_1_2.', 'Apply.'],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8.1'],
    }),

    finding({
      rule: 'gcp.cloudsql.require_ssl',
      passed: sqlWithoutRequireSsl.length === 0,
      severity: 'high',
      current: {
        summary: sqlWithoutRequireSsl.length === 0
          ? `All ${sqlCount} Cloud SQL instance(s) require SSL.`
          : `${sqlWithoutRequireSsl.length} of ${sqlCount} Cloud SQL instance(s) do NOT require SSL.`,
        observations: { without_require_ssl: sqlWithoutRequireSsl },
      },
      target: { summary: 'Cloud SQL prod instances have ipConfiguration.requireSsl=true.', rationale: 'NIST SC-8. DB traffic encrypted in transit.' },
      gap: sqlWithoutRequireSsl.length === 0 ? undefined : {
        description: 'DB connections may be plaintext.',
        affected_resources: sqlWithoutRequireSsl.map<AffectedResource>((n: string) => ({
          type: 'google_sql_database_instance', identifier: n, name: n, attributes: { requireSsl: false },
        })),
      },
      remediation: sqlWithoutRequireSsl.length === 0 ? undefined : {
        summary: 'Set requireSsl=true via Terraform.',
        options: [{
          approach: 'Update Cloud SQL ip_configuration.',
          mechanism: 'terraform',
          owner_team: 'SRE',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'medium', notes: 'Clients must connect with SSL; coordinate.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per instance.' },
          steps: ['Update client connection strings.', 'Set require_ssl=true in Terraform.', 'Apply.'],
          example_code: 'resource "google_sql_database_instance" "main" {\n  settings { ip_configuration { require_ssl = true } }\n}',
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['sc-8'],
    }),
  ];

  const thirdParty = detectThirdParty({});
  return { provider: 'gcp', project_id: ctx.project, evidence, findings, warnings, third_party_tools_detected: thirdParty };
}
