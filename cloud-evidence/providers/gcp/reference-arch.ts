/**
 * GCP FedRAMP reference-architecture audit (GCP-CHK).
 *
 * Checks a running GCP project/org against the hardening a FedRAMP-compliant build
 * is expected to have, derived clean-room from the Coalfire GCP RAMPpak reference
 * architecture (research report 04 — idea source, MIT; no code copied). Emitted as
 * its own `AUDIT-REFARCH-GCP.json` evidence file so findings flow into the NIST
 * 800-53 benchmark, OSCAL, the crosswalk, and the signed manifest.
 *
 * Read-only via the GCP Proxy guardrail. Org-scoped checks (Assured Workloads,
 * VPC-SC, SCC, org log sink) gracefully WARN when no org is configured/accessible —
 * never a false failure. Many googleapis method paths are best-effort; on error a
 * check degrades to a warning rather than a finding.
 */
import * as gcpAuth from '../../core/auth/gcp.ts';
import { diagnoseGcpError } from '../../core/error-diagnostics.ts';
import type { EvidenceFile, Finding, ProviderBlock, RawEvidence } from '../../core/envelope.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

export interface GcpRefArchCtx { runId: string; frmrVersion: string; organizationId?: string | null; }

export async function collectGcpReferenceArch(project: string, ctx: GcpRefArchCtx): Promise<EvidenceFile> {
  const findings: Finding[] = [];
  const warnings: string[] = [];
  const evidence: RawEvidence[] = [];
  const org = ctx.organizationId ?? null;

  // 1) Assured Workloads enrollment (FedRAMP Moderate) — org-scoped.
  if (org) {
    try {
      const aw = await gcpAuth.googleClient<any>('assuredworkloads', 'v1');
      const r = await aw.organizations.locations.workloads.list({ parent: `organizations/${org}/locations/us` });
      const ws = r.data.workloads ?? [];
      const fr = ws.filter((w: any) => /FEDRAMP_MODERATE|FEDRAMP_HIGH/.test(w.complianceRegime ?? ''));
      evidence.push(ev('assuredworkloads.workloads', { count: ws.length, fedramp: fr.length }));
      findings.push(finding({
        rule: 'gcp.assured_workloads.fedramp', passed: fr.length > 0, severity: 'high',
        current: { summary: `${fr.length} FedRAMP Assured Workload(s) of ${ws.length}.`, observations: { fedramp: fr.length } },
        target: { summary: 'In-scope projects sit under an Assured Workloads folder with the FedRAMP Moderate (or High) compliance regime and US data location.', rationale: 'NIST SA-9, AC-3, SC-7. On GCP, Assured Workloads is the compliance boundary.' },
        gap: { description: 'No FedRAMP Assured Workload found in the organization.', affected_resources: [{ type: 'gcp_assured_workload', identifier: `organizations/${org}`, attributes: {} }] },
        remediation: { summary: 'Create an Assured Workloads folder with the FedRAMP Moderate regime and migrate in-scope projects into it.', options: [{ approach: 'Provision via Assured Workloads + Terraform.', mechanism: 'terraform', steps: ['Create AW folder (FEDRAMP_MODERATE, US)', 'Move in-scope projects under it'] }] },
        nist_controls: ['sa-9', 'ac-3', 'sc-7'],
      }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'assuredworkloads.workloads.list', 'assuredworkloads.workloads.list (roles/assuredworkloads.reader, org scope)')); }
  } else { warnings.push('Assured Workloads check skipped: no organization_id configured.'); }

  // 2) Organization Policy constraints baseline.
  try {
    const op = await gcpAuth.googleClient<any>('orgpolicy', 'v2');
    const r = await op.projects.policies.list({ parent: `projects/${project}` });
    const names = (r.data.policies ?? []).map((p: any) => (p.name ?? '').split('/').pop());
    const expected = ['compute.requireOsLogin', 'iam.disableServiceAccountKeyCreation', 'storage.uniformBucketLevelAccess', 'compute.vmExternalIpAccess', 'gcp.resourceLocations'];
    const present = expected.filter((c) => names.includes(c));
    evidence.push(ev('orgpolicy.constraints', { present, total_policies: names.length }));
    findings.push(finding({
      rule: 'gcp.org_policy.baseline_constraints', passed: present.length >= 3, severity: 'medium',
      current: { summary: `${present.length}/${expected.length} baseline org-policy constraints set (${present.join(', ') || 'none'}).`, observations: { present } },
      target: { summary: 'Baseline Org Policy constraints are enforced: OS Login, disable SA-key creation, uniform bucket-level access, restrict VM external IPs, resource-location restriction.', rationale: 'NIST AC-3, CM-7, CM-6. Preventive org guardrails (the GCP analog of AWS SCPs).' },
      gap: { description: 'Fewer than 3 baseline org-policy constraints are enforced on this project.', affected_resources: [{ type: 'gcp_org_policy', identifier: `projects/${project}`, attributes: {} }] },
      remediation: { summary: 'Enforce the baseline constraints at the org/folder level.', options: [{ approach: 'Terraform google_org_policy_policy for each constraint.', mechanism: 'terraform', steps: ['Set compute.requireOsLogin = true', 'iam.disableServiceAccountKeyCreation = true', 'storage.uniformBucketLevelAccess = true', 'compute.vmExternalIpAccess deny-all'] }] },
      nist_controls: ['ac-3', 'cm-7', 'cm-6'],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'orgpolicy.projects.policies.list', 'orgpolicy.policies.list (roles/orgpolicy.policyViewer)')); }

  // 3) VPC Service Controls perimeter — org-scoped.
  if (org) {
    try {
      const acm = await gcpAuth.googleClient<any>('accesscontextmanager', 'v1');
      const pol = await acm.accessPolicies.list({ parent: `organizations/${org}` });
      const policies = pol.data.accessPolicies ?? [];
      let perimeters = 0;
      for (const p of policies) {
        try { const sp = await acm.accessPolicies.servicePerimeters.list({ parent: p.name }); perimeters += (sp.data.servicePerimeters ?? []).length; } catch { /* */ }
      }
      evidence.push(ev('vpcsc.perimeters', { access_policies: policies.length, perimeters }));
      findings.push(finding({
        rule: 'gcp.vpc_service_controls.perimeter', passed: perimeters > 0, severity: 'high',
        current: { summary: `${perimeters} VPC Service Controls perimeter(s) across ${policies.length} access policy(ies).`, observations: { perimeters } },
        target: { summary: 'A VPC Service Controls service perimeter encloses in-scope projects, restricting API access to mitigate data exfiltration.', rationale: 'NIST AC-4, SC-7. Top GCP data-exfil control.' },
        gap: { description: 'No VPC Service Controls perimeter found.', affected_resources: [{ type: 'gcp_vpc_sc_perimeter', identifier: `organizations/${org}`, attributes: {} }] },
        remediation: { summary: 'Create a service perimeter enclosing in-scope projects with restricted services.', options: [{ approach: 'Terraform google_access_context_manager_service_perimeter.', mechanism: 'terraform', steps: ['Create an access policy', 'Define a regular perimeter with in-scope projects', 'Set restricted_services (storage, bigquery, ...)'] }] },
        nist_controls: ['ac-4', 'sc-7'],
      }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'accesscontextmanager.accessPolicies.list', 'accesscontextmanager.policies.list (roles/accesscontextmanager.policyReader, org scope)')); }
  } else { warnings.push('VPC Service Controls check skipped: no organization_id configured.'); }

  // 4) Per-service CMEK (Compute disks + GCS buckets sampled).
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    const r = await compute.disks.aggregatedList({ project, maxResults: 200 });
    let disks = 0; let cmek = 0;
    for (const [, scoped] of Object.entries<any>(r.data.items ?? {})) {
      for (const d of scoped.disks ?? []) { disks++; if (d.diskEncryptionKey?.kmsKeyName) cmek++; }
    }
    let buckets = 0; let bucketCmek = 0;
    try {
      const storage = await gcpAuth.googleClient<any>('storage', 'v1');
      const b = await storage.buckets.list({ project });
      for (const bk of b.data.items ?? []) { buckets++; if (bk.encryption?.defaultKmsKeyName) bucketCmek++; }
    } catch { /* */ }
    evidence.push(ev('cmek.coverage', { disks, disks_cmek: cmek, buckets, buckets_cmek: bucketCmek }));
    const totalEnc = disks + buckets; const totalCmek = cmek + bucketCmek;
    findings.push(finding({
      rule: 'gcp.cmek.customer_managed_encryption', passed: totalEnc === 0 || totalCmek > 0, severity: 'high',
      current: { summary: `CMEK: ${cmek}/${disks} disks, ${bucketCmek}/${buckets} buckets use a customer-managed Cloud KMS key.`, observations: { disks, cmek, buckets, bucketCmek } },
      target: { summary: 'In-scope resources are encrypted with customer-managed Cloud KMS keys (CMEK), not Google-managed default keys.', rationale: 'NIST SC-12, SC-28(1).' },
      gap: { description: 'No customer-managed encryption keys detected on disks/buckets.', affected_resources: [{ type: 'gcp_kms_cmek', identifier: `projects/${project}`, attributes: {} }] },
      remediation: { summary: 'Configure CMEK on disks/buckets/SQL/BigQuery from a managed keyring.', options: [{ approach: 'Terraform: set kms_key_self_link / default_kms_key_name.', mechanism: 'terraform', steps: ['Create a Cloud KMS keyring + keys', 'Set CMEK on disks (disk_encryption_key)', 'Set bucket default_kms_key_name'] }] },
      nist_controls: ['sc-12', 'sc-28', 'sc-28.1'],
      cross_ksi_dependencies: [{ ksi_id: 'KSI-SVC-RUD', relationship: 'shares-remediation', note: 'Data-at-rest encryption.' }],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.disks.aggregatedList', 'compute.disks.list (roles/compute.viewer)')); }

  // 5) Data-access audit logging configured (project IAM audit configs).
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({ resource: `projects/${project}`, requestBody: { options: { requestedPolicyVersion: 3 } } });
    const auditConfigs = r.data.auditConfigs ?? [];
    const dataAccess = auditConfigs.some((c: any) => (c.auditLogConfigs ?? []).some((l: any) => l.logType === 'DATA_READ' || l.logType === 'DATA_WRITE'));
    evidence.push(ev('logging.audit_configs', { audit_configs: auditConfigs.length, data_access: dataAccess }));
    findings.push(finding({
      rule: 'gcp.logging.data_access_audit', passed: dataAccess, severity: 'medium',
      current: { summary: dataAccess ? 'Data-access audit logging (DATA_READ/DATA_WRITE) is configured.' : 'No data-access audit logging configured.', observations: { audit_configs: auditConfigs.length, dataAccess } },
      target: { summary: 'Data-access audit logs (DATA_READ/DATA_WRITE) are enabled and exported to a durable, CMEK-protected sink.', rationale: 'NIST AU-2, AU-12.' },
      gap: { description: 'Data-access audit logging is not enabled — sensitive read/write activity is not recorded.', affected_resources: [{ type: 'gcp_project_audit_config', identifier: `projects/${project}`, attributes: {} }] },
      remediation: { summary: 'Enable DATA_READ/DATA_WRITE audit logging in the project IAM policy.', options: [{ approach: 'Terraform google_project_iam_audit_config.', mechanism: 'terraform', steps: ['Add audit_config for allServices with DATA_READ + DATA_WRITE', 'Export to a CMEK-encrypted sink'] }] },
      nist_controls: ['au-2', 'au-12'],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy', 'resourcemanager.projects.getIamPolicy (roles/iam.securityReviewer)')); }

  // 6) Security Command Center enabled — org-scoped.
  if (org) {
    try {
      const scc = await gcpAuth.googleClient<any>('securitycenter', 'v1');
      const r = await scc.organizations.sources.list({ parent: `organizations/${org}` });
      const sources = (r.data.sources ?? []).length;
      evidence.push(ev('scc.sources', { sources }));
      findings.push(finding({
        rule: 'gcp.scc.enabled', passed: sources > 0, severity: 'medium',
        current: { summary: `Security Command Center exposes ${sources} finding source(s).`, observations: { sources } },
        target: { summary: 'Security Command Center (Premium) is enabled with detectors active — GCP parity to AWS Security Hub/GuardDuty.', rationale: 'NIST CA-7, RA-5, SI-4.' },
        gap: { description: 'Security Command Center has no accessible sources.', affected_resources: [{ type: 'gcp_scc', identifier: `organizations/${org}`, attributes: {} }] },
        remediation: { summary: 'Enable SCC Premium and its built-in detectors.', options: [{ approach: 'Enable SCC Premium tier for the org.', mechanism: 'console', steps: ['Enable Security Command Center Premium', 'Confirm Security Health Analytics + Event Threat Detection active'] }] },
        nist_controls: ['ca-7', 'ra-5', 'si-4'],
      }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'securitycenter.organizations.sources.list', 'securitycenter.sources.list (roles/securitycenter.adminViewer, org scope)')); }
  } else { warnings.push('Security Command Center check skipped: no organization_id configured.'); }

  // 7) Cloud NAT for private egress + instances without external IPs.
  try {
    const compute = await gcpAuth.googleClient<any>('compute', 'v1');
    const routers = await compute.routers.aggregatedList({ project, maxResults: 200 });
    let nats = 0;
    for (const [, scoped] of Object.entries<any>(routers.data.items ?? {})) for (const r of scoped.routers ?? []) nats += (r.nats ?? []).length;
    const inst = await compute.instances.aggregatedList({ project, maxResults: 200 });
    let instances = 0; let external = 0;
    for (const [, scoped] of Object.entries<any>(inst.data.items ?? {})) for (const i of scoped.instances ?? []) {
      instances++;
      if ((i.networkInterfaces ?? []).some((ni: any) => (ni.accessConfigs ?? []).some((ac: any) => ac.natIP))) external++;
    }
    evidence.push(ev('network.nat_and_external_ips', { nats, instances, external_ip_instances: external }));
    findings.push(finding({
      rule: 'gcp.network.private_egress', passed: instances === 0 || (nats > 0 && external === 0), severity: 'medium',
      current: { summary: `${nats} Cloud NAT(s); ${external}/${instances} instance(s) have an external IP.`, observations: { nats, external } },
      target: { summary: 'Private instances egress through Cloud NAT and have no external IPs.', rationale: 'NIST SC-7, AC-4.' },
      gap: { description: 'Instances have external IPs and/or there is no Cloud NAT for private egress.', affected_resources: [{ type: 'gcp_compute_instance', identifier: `projects/${project}`, attributes: { external_ip_instances: external } }] },
      remediation: { summary: 'Remove external IPs and route egress through Cloud NAT.', options: [{ approach: 'Terraform Cloud Router + NAT; drop accessConfigs.', mechanism: 'terraform', steps: ['Create Cloud Router + NAT', 'Remove instance external IPs (enforce via org policy)'] }] },
      nist_controls: ['sc-7', 'ac-4'],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'compute.instances.aggregatedList', 'compute.instances.list (roles/compute.viewer)')); }

  // 8) Least-privilege: no service accounts bound to primitive roles.
  try {
    const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
    const r = await crm.projects.getIamPolicy({ resource: `projects/${project}`, requestBody: { options: { requestedPolicyVersion: 3 } } });
    const primitive = new Set(['roles/owner', 'roles/editor']);
    const offenders: string[] = [];
    for (const b of r.data.bindings ?? []) {
      if (!primitive.has(b.role)) continue;
      for (const m of b.members ?? []) if (String(m).startsWith('serviceAccount:')) offenders.push(`${m} → ${b.role}`);
    }
    evidence.push(ev('iam.primitive_role_sas', { offenders: offenders.length }));
    findings.push(finding({
      rule: 'gcp.iam.no_primitive_role_service_accounts', passed: offenders.length === 0, severity: 'high',
      current: { summary: `${offenders.length} service account(s) bound to a primitive role (owner/editor).`, observations: { offenders: offenders.slice(0, 50) } },
      target: { summary: 'Service accounts hold only narrow predefined/custom roles — never owner/editor.', rationale: 'NIST AC-6, AC-6(1). Least privilege.' },
      gap: { description: 'Service accounts are bound to primitive owner/editor roles.', affected_resources: offenders.slice(0, 50).map((o) => ({ type: 'gcp_iam_binding', identifier: o, attributes: {} })) },
      remediation: { summary: 'Replace primitive-role SA bindings with least-privilege predefined roles.', options: [{ approach: 'Terraform: scope SA roles to specific predefined roles.', mechanism: 'terraform', steps: ['Identify required permissions', 'Bind narrow predefined roles', 'Remove owner/editor bindings'] }] },
      nist_controls: ['ac-6', 'ac-6.1'],
      cross_ksi_dependencies: [{ ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'Least privilege.' }],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.projects.getIamPolicy (primitive roles)', 'resourcemanager.projects.getIamPolicy (roles/iam.securityReviewer)')); }

  // 9) DNS query logging enabled.
  try {
    const dns = await gcpAuth.googleClient<any>('dns', 'v1');
    const r = await dns.policies.list({ project });
    const policies = r.data.policies ?? [];
    const logging = policies.filter((p: any) => p.enableLogging).length;
    evidence.push(ev('dns.query_logging', { policies: policies.length, logging }));
    findings.push(finding({
      rule: 'gcp.dns.query_logging', passed: policies.length === 0 || logging > 0, severity: 'low',
      current: { summary: `${logging}/${policies.length} DNS policy(ies) have query logging on.`, observations: { logging } },
      target: { summary: 'DNS query logging is enabled on in-scope VPC DNS policies.', rationale: 'NIST AU-2, SC-7. DNS exfil/C2 detection.' },
      gap: { description: 'No DNS policy has query logging enabled.', affected_resources: [{ type: 'gcp_dns_policy', identifier: `projects/${project}`, attributes: {} }] },
      remediation: { summary: 'Enable query logging on the VPC DNS policy.', options: [{ approach: 'Terraform google_dns_policy enable_logging = true.', mechanism: 'terraform', steps: ['Create/Update DNS policy with enable_logging = true', 'Attach to in-scope networks'] }] },
      nist_controls: ['au-2', 'sc-7'],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'dns.policies.list', 'dns.policies.list (roles/dns.reader)')); }

  // 10) Curated API enablement vs an allow-list (attack-surface reduction).
  try {
    const allow = (process.env.CLOUD_EVIDENCE_GCP_API_ALLOWLIST || '').split(',').map((s) => s.trim()).filter(Boolean);
    const su = await gcpAuth.googleClient<any>('serviceusage', 'v1');
    const r = await su.services.list({ parent: `projects/${project}`, filter: 'state:ENABLED', pageSize: 200 });
    const enabled = (r.data.services ?? []).map((s: any) => (s.config?.name ?? s.name ?? '').split('/').pop());
    const unexpected = allow.length ? enabled.filter((s: string) => !allow.includes(s)) : [];
    evidence.push(ev('serviceusage.enabled', { enabled_count: enabled.length, allowlist: allow.length, unexpected: unexpected.length }));
    findings.push(finding({
      rule: 'gcp.serviceusage.curated_apis', passed: allow.length === 0 || unexpected.length === 0, severity: 'low',
      current: { summary: allow.length ? `${unexpected.length} enabled API(s) outside the allow-list (${enabled.length} enabled).` : `${enabled.length} API(s) enabled; no allow-list configured.`, observations: { unexpected: unexpected.slice(0, 50) } },
      target: { summary: 'Only the APIs required by the workload are enabled (set CLOUD_EVIDENCE_GCP_API_ALLOWLIST to enforce).', rationale: 'NIST CM-7. Attack-surface reduction.' },
      gap: { description: 'APIs are enabled beyond the approved allow-list.', affected_resources: unexpected.slice(0, 50).map((s: string) => ({ type: 'gcp_service_api', identifier: s, attributes: {} })) },
      remediation: { summary: 'Disable unneeded APIs; enforce an enabled-API allow-list via org policy.', options: [{ approach: 'gcloud services disable + gcp.restrictServiceUsage org policy.', mechanism: 'cli', steps: ['Disable unused services', 'Set the restrictServiceUsage org policy'] }] },
      nist_controls: ['cm-7'],
      note: allow.length ? undefined : 'Informational until CLOUD_EVIDENCE_GCP_API_ALLOWLIST is set.',
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'serviceusage.services.list', 'serviceusage.services.list (roles/serviceusage.serviceUsageViewer)')); }

  // 11) Cloud SQL instances are private (no public IPv4).
  try {
    const sql = await gcpAuth.googleClient<any>('sqladmin', 'v1');
    const r = await sql.instances.list({ project });
    const instances = r.data.items ?? [];
    const publicSql = instances.filter((i: any) => i.settings?.ipConfiguration?.ipv4Enabled === true).length;
    evidence.push(ev('cloudsql.public_ip', { instances: instances.length, public: publicSql }));
    findings.push(finding({
      rule: 'gcp.cloudsql.private_only', passed: instances.length === 0 || publicSql === 0, severity: 'medium',
      current: { summary: `${publicSql}/${instances.length} Cloud SQL instance(s) have a public IPv4.`, observations: { public: publicSql } },
      target: { summary: 'Cloud SQL instances use Private Service Access only (no public IPv4).', rationale: 'NIST SC-7, AC-4.' },
      gap: { description: 'Cloud SQL instances are reachable over a public IP.', affected_resources: [{ type: 'gcp_sql_instance', identifier: `projects/${project}`, attributes: { public: publicSql } }] },
      remediation: { summary: 'Disable public IP; use Private Service Access.', options: [{ approach: 'Terraform: ip_configuration ipv4_enabled = false + private_network.', mechanism: 'terraform', steps: ['Enable Private Service Access on the VPC', 'Set ipv4_enabled = false', 'Set private_network'] }] },
      nist_controls: ['sc-7', 'ac-4'],
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'sqladmin.instances.list', 'cloudsql.instances.list (roles/cloudsql.viewer)')); }

  // 12) Org admin via groups (not individual users) — org-scoped.
  if (org) {
    try {
      const crm = await gcpAuth.googleClient<any>('cloudresourcemanager', 'v3');
      const r = await crm.organizations.getIamPolicy({ resource: `organizations/${org}`, requestBody: { options: { requestedPolicyVersion: 3 } } });
      const adminRoles = new Set(['roles/resourcemanager.organizationAdmin', 'roles/owner', 'roles/iam.organizationRoleAdmin']);
      let userAdmins = 0; let groupAdmins = 0;
      for (const b of r.data.bindings ?? []) {
        if (!adminRoles.has(b.role)) continue;
        for (const m of b.members ?? []) { if (String(m).startsWith('user:')) userAdmins++; else if (String(m).startsWith('group:')) groupAdmins++; }
      }
      evidence.push(ev('iam.org_admin_membership', { userAdmins, groupAdmins }));
      findings.push(finding({
        rule: 'gcp.iam.group_based_org_admin', passed: userAdmins === 0, severity: 'medium',
        current: { summary: `Org admin roles: ${userAdmins} individual user binding(s), ${groupAdmins} group binding(s).`, observations: { userAdmins, groupAdmins } },
        target: { summary: 'Org-admin roles are bound to managed groups, not individual users (and 2-Step Verification is enforced org-wide).', rationale: 'NIST AC-2, AC-6, IA-2.' },
        gap: { description: 'Org-admin roles are bound directly to individual users.', affected_resources: [{ type: 'gcp_org_iam_binding', identifier: `organizations/${org}`, attributes: { userAdmins } }] },
        remediation: { summary: 'Move admin grants to a restricted group; enforce 2SV.', options: [{ approach: 'Bind admin roles to a group; remove user bindings.', mechanism: 'terraform', steps: ['Create an org-admins group', 'Bind admin roles to the group', 'Remove individual user bindings', 'Enforce 2SV in Admin console'] }] },
        nist_controls: ['ac-2', 'ac-6', 'ia-2'],
      }));
    } catch (e) { warnings.push(diagnoseGcpError(e, 'cloudresourcemanager.organizations.getIamPolicy', 'resourcemanager.organizations.getIamPolicy (org scope)')); }
  } else { warnings.push('Group-based org-admin check skipped: no organization_id configured.'); }

  // 13) IaC state integrity: GCS state bucket CMEK + versioning.
  try {
    const storage = await gcpAuth.googleClient<any>('storage', 'v1');
    const b = await storage.buckets.list({ project });
    const stateBuckets = (b.data.items ?? []).filter((bk: any) => /tf-?state|terraform.*state/i.test(bk.name ?? ''));
    const good = stateBuckets.filter((bk: any) => bk.encryption?.defaultKmsKeyName && bk.versioning?.enabled).length;
    evidence.push(ev('iac.state_integrity', { state_buckets: stateBuckets.length, hardened: good }));
    const found = stateBuckets.length > 0;
    findings.push(finding({
      rule: 'gcp.iac.state_integrity', passed: !found || good === stateBuckets.length, severity: 'low',
      current: { summary: found ? `${good}/${stateBuckets.length} TF-state bucket(s) are CMEK-encrypted + versioned.` : 'No Terraform-state GCS bucket detected by name heuristic.', observations: { state_buckets: stateBuckets.length, hardened: good } },
      target: { summary: 'Terraform-state GCS buckets are CMEK-encrypted and versioned, protecting IaC integrity.', rationale: 'NIST SC-28, CM-2(2).' },
      gap: { description: 'A Terraform-state bucket is not CMEK-encrypted or not versioned.', affected_resources: stateBuckets.map((bk: any) => ({ type: 'gcp_storage_bucket', identifier: bk.name, attributes: {} })) },
      remediation: { summary: 'Enable CMEK + versioning on the state bucket.', options: [{ approach: 'Terraform: encryption.default_kms_key_name + versioning.', mechanism: 'terraform', steps: ['Set default_kms_key_name (CMEK)', 'Enable versioning'] }] },
      nist_controls: ['sc-28', 'cm-2.2'],
      note: found ? undefined : 'Heuristic by bucket name; informational when no state bucket is detected.',
    }));
  } catch (e) { warnings.push(diagnoseGcpError(e, 'storage.buckets.list (IaC state)', 'storage.buckets.list (roles/storage.admin or roles/viewer)')); }

  const provider: ProviderBlock = { provider: 'gcp', project_id: project, evidence, findings, warnings };
  return {
    ksi_id: 'AUDIT-REFARCH-GCP',
    ksi_name: 'GCP FedRAMP Reference-Architecture Audit',
    ksi_statement: 'Audit the running GCP project/org against FedRAMP reference-architecture hardening expectations (Coalfire GCP RAMPpak-derived): Assured Workloads, Org Policy constraints, VPC Service Controls, CMEK, data-access audit logging, Security Command Center, private egress, least-privilege service accounts, DNS logging, curated APIs, private Cloud SQL, group-based org admin, and IaC state integrity.',
    scope: 'CLOUD',
    frmr_version: ctx.frmrVersion,
    run_id: ctx.runId,
    collected_at: new Date().toISOString(),
    providers: [provider],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings,
      missing_evidence: [],
      alternatives_in_play: 0,
    },
    nist_controls: ['sa-9', 'ac-3', 'ac-4', 'sc-7', 'sc-12', 'sc-28', 'au-2', 'ac-6', 'cm-7'],
  };
}
