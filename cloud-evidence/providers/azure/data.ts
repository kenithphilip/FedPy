/**
 * Azure data-plane KSI collectors.
 *
 *   - KSI-SVC-RUD — Removing Unwanted Data. Operator must be able to remove
 *     federal customer data on request and prove the removal. Azure-canonical
 *     signals are blob soft-delete (reversible delete window for audit) and
 *     storage lifecycle-management policies (automation for deletion).
 *
 *   - KSI-SVC-VCM — Validating Communications (HYBRID). Inter-service traffic
 *     authenticity / integrity. Azure-canonical signals: Application Gateway
 *     mTLS, API Management client-cert validation, or an AKS Istio service-
 *     mesh add-on. Off-Azure service mesh (Linkerd / Consul / Cilium) lives
 *     in the alternative satisfier.
 *
 *   - KSI-SVC-VRI — Validating Resource Integrity. Storage-side integrity
 *     primitives: blob versioning (delete history) OR an immutability
 *     policy (WORM enforcement). Either satisfies the cryptographic-integrity
 *     intent for storage; the alt satisfier covers Azure Confidential Compute
 *     attestation for VM/container workloads.
 *
 * All via Azure Resource Graph; no new permissions beyond AZ-1's Reader role.
 */
import * as azure from '../../core/auth/azure.ts';
import type { ProviderBlock, RawEvidence, Finding, AlternativeSatisfier } from '../../core/envelope.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { finding } from '../../core/findings.ts';

function ev(source: string, data: unknown): RawEvidence {
  return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data };
}

async function runKql(subscriptions: string[], query: string): Promise<{ rows: any[]; error?: string }> {
  if (subscriptions.length === 0) return { rows: [], error: 'No subscriptions configured (config.azure.subscriptions is empty).' };
  let client: any;
  try { client = azure.resourceGraph(); }
  catch (e: any) { return { rows: [], error: `Azure Resource Graph client construction failed: ${e?.message ?? e}` }; }
  const rows: any[] = [];
  let skipToken: string | undefined;
  let pages = 0;
  try {
    do {
      const r = await client.resources({
        subscriptions, query,
        options: { top: 1000, resultFormat: 'objectArray', ...(skipToken ? { $skipToken: skipToken } : {}) },
      });
      const data = Array.isArray(r?.data) ? r.data : [];
      rows.push(...data);
      skipToken = r?.$skipToken ?? r?.skipToken ?? undefined;
    } while (skipToken && ++pages < 50);
  } catch (e: any) {
    return { rows, error: `Resource Graph query failed: ${e?.message ?? e}` };
  }
  return { rows };
}

function subscriptionsOf(ctx: CollectorContext): string[] {
  const list = ctx.azure?.subscription_ids ?? [];
  if (list.length) return list;
  const one = ctx.azure?.subscription_id;
  return one ? [one] : [];
}

// =====================================================================
// KSI-SVC-RUD — Removing Unwanted Data
// =====================================================================
export async function collectSvcRud(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Storage accounts — blob soft-delete posture.
  // Blob soft-delete keeps deleted blobs recoverable for a retention window;
  // that window is the audit trail you need to prove "we deleted X on date Y".
  // A finite, reasonable window (1-90 days) is the goal. Disabled = no audit.
  const storage = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend sdEnabled = tobool(properties.deleteRetentionPolicy.enabled), ' +
    'sdDays = toint(properties.deleteRetentionPolicy.days) ' +
    '| project id, name, subscriptionId, sdEnabled, sdDays');
  if (storage.error) warnings.push(storage.error);

  const total = storage.rows.length;
  const softDeleteOff = storage.rows.filter((s: any) => s.sdEnabled !== true);
  const overlyLong = storage.rows.filter((s: any) => s.sdEnabled === true && Number(s.sdDays ?? 0) > 90);

  evidence.push(ev('resourcegraph.storage_blob_soft_delete', {
    total,
    soft_delete_off: softDeleteOff.length,
    overly_long_retention: overlyLong.length,
    sample: storage.rows.slice(0, 20),
  }));

  // 2) Storage lifecycle management policies — automated retention/deletion.
  // microsoft.storage/storageaccounts/managementpolicies is the child resource.
  const lifecycle = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts/managementpolicies" ' +
    '| project id, name, subscriptionId');
  if (lifecycle.error) warnings.push(lifecycle.error);
  evidence.push(ev('resourcegraph.storage_lifecycle_policies', {
    total: lifecycle.rows.length,
    sample: lifecycle.rows.slice(0, 10),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Application-layer deletion + database TTL (with audit log)',
      description: 'Customer data lives in DB / app storage with row-level TTL and an application-emitted audit event per delete.',
      evidence_required: ['Deletion-event audit-log sample', 'DB TTL or app retention configuration', 'Customer-deletion runbook'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: blob soft-delete enabled with finite window --------
  const softDeletePassed = total === 0 || (softDeleteOff.length === 0 && overlyLong.length === 0);
  findings.push(finding({
    rule: 'azure.svc.rud.blob_soft_delete_finite_window', passed: softDeletePassed, severity: 'medium',
    current: {
      summary: total === 0
        ? 'No storage accounts to evaluate.'
        : softDeleteOff.length === 0 && overlyLong.length === 0
          ? `All ${total} storage account(s) have blob soft-delete enabled with retention ≤ 90 days.`
          : `${softDeleteOff.length}/${total} storage account(s) have soft-delete disabled; ${overlyLong.length} have retention > 90 days (excessive — defeats actual deletion).`,
      observations: { total, soft_delete_off: softDeleteOff.length, overly_long_retention: overlyLong.length },
    },
    target: { summary: 'Every storage account has blob soft-delete enabled with retention between 1 and 90 days — gives an audit window without blocking actual deletion on customer request.', rationale: 'NIST MP-6, SI-12. Operator must be able to delete data and prove the deletion; an audit window of 1-90 days is the canonical compromise.' },
    gap: { description: 'Either no audit window (soft-delete disabled) or so long a window that "deletion on request" can\'t actually be honored within SLA.', affected_resources: [...softDeleteOff, ...overlyLong].slice(0, 50).map((s: any) => ({ type: 'azure_storage_account', identifier: s.id, attributes: { name: s.name, soft_delete: s.sdEnabled, retention_days: s.sdDays } })) },
    remediation: {
      summary: 'Enable blob soft-delete with a 7-30 day retention window (operator-tunable to your customer SLA).',
      options: [
        { approach: 'az CLI per account.', mechanism: 'cli', steps: ['az storage account blob-service-properties update --account-name <acct> --enable-delete-retention true --delete-retention-days 30'] },
        { approach: 'Terraform azurerm_storage_account.blob_properties.delete_retention_policy.', mechanism: 'terraform', steps: ['Set delete_retention_policy { days = 30 }', 'Apply'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['mp-6', 'si-12'],
  }));

  // -------- Finding 2: lifecycle management policies present --------
  // Vacuously pass if there are no storage accounts; otherwise want at least
  // one management policy attached so retention is automated rather than
  // depending on operator memory.
  const lifecyclePassed = total === 0 || lifecycle.rows.length >= 1;
  findings.push(finding({
    rule: 'azure.svc.rud.lifecycle_management_present', passed: lifecyclePassed, severity: 'medium',
    current: {
      summary: total === 0
        ? 'No storage accounts to evaluate.'
        : lifecycle.rows.length >= 1
          ? `${lifecycle.rows.length} storage-lifecycle management policy(ies) found — retention is automated.`
          : `No lifecycle management policies across ${total} storage account(s) — retention/deletion relies on operator memory.`,
      observations: { total_storage: total, lifecycle_policies: lifecycle.rows.length },
    },
    target: { summary: 'At least one storage account has a lifecycle-management policy attached — retention is automated, not manual.', rationale: 'NIST MP-6. Manual retention drifts; automated retention is the only one that actually fires under load.' },
    gap: { description: 'Retention/deletion is fully manual — likely to drift.', affected_resources: [{ type: 'azure_storage_management_policy', identifier: 'none', attributes: { storage_accounts: total } }] },
    remediation: {
      summary: 'Attach a Blob Storage lifecycle-management policy: tier-down to Cool/Archive after N days, delete after M days.',
      options: [
        { approach: 'Terraform azurerm_storage_management_policy.', mechanism: 'terraform', steps: [
          'Declare azurerm_storage_management_policy.rule with actions.base_blob.delete_after_days_since_modification_greater_than = M',
          'Bind to the storage account; apply',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['mp-6'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}

// =====================================================================
// KSI-SVC-VCM — Validating Communications (HYBRID)
// =====================================================================
export async function collectSvcVcm(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Application Gateway mTLS — listeners with client-cert verification.
  // AGW exposes mTLS via the `sslProfiles` array; we look for a profile whose
  // clientAuthConfiguration is configured. Resource Graph reflects this as
  // properties.sslProfiles, each having clientAuthConfiguration.
  const agw = await runKql(subs,
    'Resources | where type =~ "microsoft.network/applicationgateways" ' +
    '| extend mtlsProfiles = array_length(properties.sslProfiles) ' +
    '| project id, name, subscriptionId, mtlsProfiles');
  if (agw.error) warnings.push(agw.error);
  const agwsWithMtls = agw.rows.filter((g: any) => Number(g.mtlsProfiles ?? 0) > 0);

  // 2) API Management — client-cert auth at gateway level.
  // microsoft.apimanagement/service resources have a hostnameConfigurations
  // array; presence of "Proxy" hostname with negotiateClientCertificate is
  // the cert-validation signal. We surface count of APIM services that
  // have any negotiateClientCertificate=true entry.
  const apim = await runKql(subs,
    'Resources | where type =~ "microsoft.apimanagement/service" ' +
    '| extend hcs = properties.hostnameConfigurations ' +
    '| project id, name, subscriptionId, hcs');
  if (apim.error) warnings.push(apim.error);
  const apimsWithClientCert = apim.rows.filter((s: any) => Array.isArray(s.hcs) && s.hcs.some((h: any) => h?.negotiateClientCertificate === true));

  // 3) AKS Istio service-mesh add-on.
  // microsoft.containerservice/managedclusters carries
  // properties.serviceMeshProfile.mode = "Istio" when the add-on is enabled.
  const aks = await runKql(subs,
    'Resources | where type =~ "microsoft.containerservice/managedclusters" ' +
    '| extend meshMode = tostring(properties.serviceMeshProfile.mode) ' +
    '| project id, name, subscriptionId, meshMode');
  if (aks.error) warnings.push(aks.error);
  const aksWithMesh = aks.rows.filter((c: any) => String(c.meshMode ?? '').toLowerCase() === 'istio');

  evidence.push(ev('resourcegraph.application_gateway_mtls', { total: agw.rows.length, with_mtls: agwsWithMtls.length, sample: agw.rows.slice(0, 10) }));
  evidence.push(ev('resourcegraph.api_management_client_cert', { total: apim.rows.length, with_client_cert: apimsWithClientCert.length, sample: apim.rows.slice(0, 10) }));
  evidence.push(ev('resourcegraph.aks_service_mesh', { total: aks.rows.length, with_istio: aksWithMesh.length, sample: aks.rows.slice(0, 10) }));

  const detectedSignals: string[] = [];
  if (agwsWithMtls.length > 0) detectedSignals.push(`${agwsWithMtls.length} Application Gateway(s) with mTLS profile`);
  if (apimsWithClientCert.length > 0) detectedSignals.push(`${apimsWithClientCert.length} API Management service(s) with client-cert validation`);
  if (aksWithMesh.length > 0) detectedSignals.push(`${aksWithMesh.length} AKS cluster(s) with Istio service-mesh add-on`);

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External service mesh on AKS (Linkerd / Consul / Cilium / Open Service Mesh)',
      description: 'mTLS enforced by a 3rd-party service mesh installed in-cluster rather than the Istio add-on.',
      evidence_required: ['Mesh manifest / Helm values', 'Sample mTLS-validated traffic capture', 'mesh control-plane audit log'],
      detected: false, detection_signals: [],
    },
    {
      via: 'Code-level mTLS via shared CA (NetClient + cert pinning)',
      description: 'mTLS terminated by application code with certificates issued from a shared internal CA.',
      evidence_required: ['CA roots inventory', 'Cert-rotation pipeline', 'Sample failed-handshake log'],
      detected: false, detection_signals: [],
    },
  ];

  const totalEnvelopes = agwsWithMtls.length + apimsWithClientCert.length + aksWithMesh.length;
  findings.push(finding({
    rule: 'azure.svc.vcm.mtls_or_service_mesh_present',
    passed: totalEnvelopes >= 1,
    severity: 'medium',
    current: {
      summary: totalEnvelopes >= 1
        ? `mTLS / service-mesh evidence: ${detectedSignals.join('; ')}.`
        : 'No Application Gateway mTLS, API Management client-cert validation, or AKS Istio add-on observed — inter-service authenticity may rely on alternative satisfiers.',
      observations: {
        application_gateways_with_mtls: agwsWithMtls.length,
        api_management_with_client_cert: apimsWithClientCert.length,
        aks_with_istio_mesh: aksWithMesh.length,
      },
    },
    target: { summary: 'At least one Azure-canonical mTLS / service-mesh primitive is in use OR a documented alternative satisfier (3rd-party mesh, code-level mTLS).', rationale: 'NIST SC-23, SI-7(1). Inter-service authenticity needs a layer-7 cryptographic envelope.' },
    gap: { description: 'No mTLS or service-mesh signal — service-to-service traffic identity may be unverified.', affected_resources: [{ type: 'azure_inter_service_authn', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Enable mTLS at one of the Azure-canonical surfaces (AGW SSL profile, APIM client-cert, AKS Istio add-on) OR document the 3rd-party mesh.',
      options: [
        { approach: 'AKS Istio service-mesh add-on.', mechanism: 'cli', steps: ['az aks mesh enable -n <aks> -g <rg>', 'Confirm STRICT mTLS via `kubectl get peerauthentication -A`'] },
        { approach: 'Application Gateway SSL profile with clientAuthConfiguration.', mechanism: 'terraform', steps: ['azurerm_application_gateway.ssl_profile { client_auth_configuration { verify_client_cert_issuer_dn = true } }'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sc-23', 'si-7.1'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}

// =====================================================================
// KSI-SVC-VRI — Validating Resource Integrity
// =====================================================================
export async function collectSvcVri(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Storage blob versioning + immutability policies.
  //  - properties.isVersioningEnabled gives us versioning (delete history)
  //  - immutability policies live at microsoft.storage/storageaccounts/blobservices/containers/immutabilityPolicies
  const storage = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend versioning = tobool(properties.isVersioningEnabled) ' +
    '| project id, name, subscriptionId, versioning');
  if (storage.error) warnings.push(storage.error);

  const immutability = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts/blobservices/containers/immutabilitypolicies" ' +
    '| project id, name, subscriptionId');
  if (immutability.error) warnings.push(immutability.error);

  const total = storage.rows.length;
  const versionedAccounts = storage.rows.filter((s: any) => s.versioning === true);
  const protectedAccountIds = new Set([
    ...versionedAccounts.map((s: any) => String(s.id ?? '').toLowerCase()),
    // Immutability policies are scoped under storage-account ids; we match
    // by storage-account substring presence.
    ...immutability.rows.map((p: any) => {
      const id = String(p.id ?? '');
      const m = id.match(/(\/subscriptions\/[^/]+\/resourcegroups\/[^/]+\/providers\/microsoft\.storage\/storageaccounts\/[^/]+)/i);
      return (m?.[1] ?? '').toLowerCase();
    }).filter(Boolean),
  ]);
  const unprotectedAccounts = storage.rows.filter((s: any) => !protectedAccountIds.has(String(s.id ?? '').toLowerCase()));

  evidence.push(ev('resourcegraph.storage_integrity', {
    total,
    with_versioning: versionedAccounts.length,
    immutability_policies: immutability.rows.length,
    protected_account_count: protectedAccountIds.size,
    unprotected: unprotectedAccounts.length,
    sample: storage.rows.slice(0, 20),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'Azure Confidential Compute (TEE attestation) for VM/container workloads',
      description: 'Workload integrity validated via Confidential VM attestation rather than storage-side WORM.',
      evidence_required: ['Attestation report sample', 'Workload-to-TEE mapping', 'Attestation key chain'],
      detected: false, detection_signals: [],
    },
  ];

  const integrityPassed = total === 0 || unprotectedAccounts.length === 0;
  findings.push(finding({
    rule: 'azure.svc.vri.storage_integrity_present', passed: integrityPassed, severity: 'medium',
    current: {
      summary: total === 0
        ? 'No storage accounts to evaluate.'
        : unprotectedAccounts.length === 0
          ? `All ${total} storage account(s) have either blob versioning or an immutability policy attached.`
          : `${unprotectedAccounts.length}/${total} storage account(s) have neither blob versioning nor an immutability policy — silent tampering / accidental overwrite has no detection path.`,
      observations: { total, with_versioning: versionedAccounts.length, immutability_policy_count: immutability.rows.length, unprotected: unprotectedAccounts.length },
    },
    target: { summary: 'Every storage account either has `isVersioningEnabled = true` OR has at least one immutability policy at the container level.', rationale: 'NIST SI-7, SI-7(1), SI-7(6). Resource integrity needs a tamper-evident primitive — versioning gives change history, immutability blocks change entirely.' },
    gap: { description: 'Unprotected storage accounts can be silently overwritten or deleted with no integrity record.', affected_resources: unprotectedAccounts.slice(0, 50).map((s: any) => ({ type: 'azure_storage_account', identifier: s.id, attributes: { name: s.name, versioning: s.versioning } })) },
    remediation: {
      summary: 'Enable blob versioning (low cost, no operational impact) OR attach a time-bound immutability policy where regulatory hold is required.',
      options: [
        { approach: 'az CLI per account — enable versioning.', mechanism: 'cli', steps: ['az storage account blob-service-properties update --account-name <acct> --enable-versioning true'] },
        { approach: 'Terraform azurerm_storage_account.blob_properties.versioning_enabled = true.', mechanism: 'terraform', steps: ['Set versioning_enabled = true; apply'] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['si-7', 'si-7.1', 'si-7.6'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
