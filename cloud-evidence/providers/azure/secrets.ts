/**
 * Azure secrets / Key Vault collector.
 *
 *   - KSI-SVC-ASM — Automating Secret Management. Three findings, all
 *     queryable via Azure Resource Graph against the management plane
 *     (no Key Vault data-plane permission needed — we read vault metadata,
 *     not the secrets / keys / certificates themselves):
 *       1. At least one Key Vault exists somewhere in the configured subs.
 *       2. Every vault has soft-delete enabled (so deletions are recoverable).
 *          Azure has made soft-delete mandatory since Feb-2025 but the field
 *          can still be `false` on older vaults imported via ARM templates,
 *          so we check explicitly.
 *       3. Every vault has either RBAC authorization (preferred) OR purge
 *          protection enabled. RBAC is the modern least-privilege model;
 *          purge protection backstops legacy access-policy vaults against
 *          permanent loss.
 *
 * Reader role is sufficient (Microsoft.KeyVault/vaults/read).
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
// KSI-SVC-ASM — Automating Secret Management
// =====================================================================
export async function collectSvcAsm(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // Key Vault inventory + posture flags. We project the three properties we
  // need so the JS side does not have to assume a particular property shape.
  const vaults = await runKql(subs,
    'Resources | where type =~ "microsoft.keyvault/vaults" ' +
    '| extend soft = tobool(properties.enableSoftDelete), ' +
    'purge = tobool(properties.enablePurgeProtection), ' +
    'rbac = tobool(properties.enableRbacAuthorization) ' +
    '| project id, name, subscriptionId, location, soft, purge, rbac');
  if (vaults.error) warnings.push(vaults.error);

  const total = vaults.rows.length;
  // Treat soft-delete as enabled unless explicitly false. (Azure now defaults
  // to true; some older vaults serialize the field as null even when active.)
  const softDeleteOff = vaults.rows.filter((v: any) => v.soft === false);
  const rbacOn = vaults.rows.filter((v: any) => v.rbac === true);
  const purgeOn = vaults.rows.filter((v: any) => v.purge === true);
  // A vault is "covered" by destructive-loss protection if it uses RBAC
  // (modern least-privilege) OR purge protection (forces a 90d hold even on
  // legacy access-policy vaults).
  const uncoveredVaults = vaults.rows.filter((v: any) => v.rbac !== true && v.purge !== true);

  evidence.push(ev('resourcegraph.key_vaults', {
    total,
    soft_delete_off: softDeleteOff.length,
    rbac_enabled: rbacOn.length,
    purge_protection_enabled: purgeOn.length,
    uncovered_vaults: uncoveredVaults.length,
    sample: vaults.rows.slice(0, 20),
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'HashiCorp Vault running in-cluster (e.g. AKS-hosted)',
      description: 'Workload-injected secrets via HC Vault sidecar / CSI driver replace static Key Vault entries.',
      evidence_required: ['HC Vault audit log sample', 'Service inventory mapping each app to a Vault role'],
      detected: false, detection_signals: [],
    },
  ];

  // -------- Finding 1: Key Vaults present --------
  findings.push(finding({
    rule: 'azure.svc.asm.key_vault_present', passed: total >= 1, severity: 'high',
    current: {
      summary: total >= 1
        ? `${total} Key Vault(s) inventoried across the configured subscriptions.`
        : 'No Azure Key Vaults observed — secrets/keys/certs may be living in env vars, app config, or source code.',
      observations: { total },
    },
    target: { summary: 'At least one Azure Key Vault exists; sensitive material lives in a managed store, not in code or env.', rationale: 'NIST IA-5, SC-12. Centralized secret storage is the precondition for rotation, audit, and revocation.' },
    gap: { description: 'No managed secret store — operators are likely keeping secrets in app config or env vars.', affected_resources: [{ type: 'azure_keyvault', identifier: 'none', attributes: {} }] },
    remediation: {
      summary: 'Provision a Key Vault per environment and migrate secrets, keys, and certificates into it.',
      options: [
        { approach: 'Terraform azurerm_key_vault + RBAC role assignments.', mechanism: 'terraform', steps: [
          'Declare azurerm_key_vault with enable_rbac_authorization = true, purge_protection_enabled = true, soft_delete_retention_days >= 7',
          'Bind Key Vault Secrets Officer to operators and Key Vault Secrets User to app identities',
          'Migrate values via azurerm_key_vault_secret resources',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ia-5', 'sc-12'],
  }));

  // -------- Finding 2: soft-delete enabled on every vault --------
  const softPassed = total === 0 || softDeleteOff.length === 0;
  findings.push(finding({
    rule: 'azure.svc.asm.key_vault_soft_delete_enabled', passed: softPassed, severity: 'high',
    current: {
      summary: total === 0
        ? 'No vaults to evaluate.'
        : softDeleteOff.length === 0
          ? `All ${total} Key Vault(s) have soft-delete enabled.`
          : `${softDeleteOff.length}/${total} Key Vault(s) have soft-delete disabled — deletions are immediately permanent.`,
      observations: { total, soft_delete_off: softDeleteOff.length },
    },
    target: { summary: 'Every Key Vault has soft-delete enabled (90-day recovery window).', rationale: 'NIST CP-9, CP-10. Soft-delete is the safety net against accidental or malicious destruction of secrets/keys/certs.' },
    gap: { description: 'Soft-delete disabled means a delete is irrecoverable — single mistake = lost secret material.', affected_resources: softDeleteOff.slice(0, 50).map((v: any) => ({ type: 'azure_keyvault', identifier: v.id, attributes: { name: v.name, soft_delete: false } })) },
    remediation: {
      summary: 'Enable soft-delete on every vault. Cannot be turned off again once enabled (by design).',
      options: [
        { approach: 'az CLI per vault.', mechanism: 'cli', steps: ['az keyvault update --name <vault> --enable-soft-delete true', 'Repeat per vault'] },
        { approach: 'Terraform azurerm_key_vault.soft_delete_retention_days.', mechanism: 'terraform', steps: ['Set soft_delete_retention_days = 90 on every azurerm_key_vault'] },
      ],
    },
    nist_controls: ['cp-9', 'cp-10'],
  }));

  // -------- Finding 3: RBAC OR purge protection on every vault --------
  const rbacOrPurgePassed = total === 0 || uncoveredVaults.length === 0;
  findings.push(finding({
    rule: 'azure.svc.asm.key_vault_rbac_or_purge_protection', passed: rbacOrPurgePassed, severity: 'medium',
    current: {
      summary: total === 0
        ? 'No vaults to evaluate.'
        : uncoveredVaults.length === 0
          ? `All ${total} Key Vault(s) use either RBAC authorization (modern) or purge protection (backstop).`
          : `${uncoveredVaults.length}/${total} Key Vault(s) use legacy access policies without purge protection — admin error or compromise could permanently destroy secrets.`,
      observations: { total, rbac_enabled: rbacOn.length, purge_protection_enabled: purgeOn.length, uncovered: uncoveredVaults.length },
    },
    target: { summary: 'Every Key Vault either enables RBAC authorization (preferred) OR enables purge protection.', rationale: 'NIST AC-3, SC-12. RBAC ties vault access to Entra ID least-privilege model; purge protection blocks immediate destruction even for legacy access-policy vaults.' },
    gap: { description: 'Legacy access-policy vaults without purge protection are one wrong delete away from total loss.', affected_resources: uncoveredVaults.slice(0, 50).map((v: any) => ({ type: 'azure_keyvault', identifier: v.id, attributes: { name: v.name, rbac: false, purge_protection: false } })) },
    remediation: {
      summary: 'Migrate vaults to RBAC authorization (preferred long-term) or at minimum turn on purge protection.',
      options: [
        { approach: 'Terraform — enable RBAC authorization on the vault.', mechanism: 'terraform', steps: [
          'Set enable_rbac_authorization = true on azurerm_key_vault',
          'Replace azurerm_key_vault_access_policy blocks with azurerm_role_assignment using Key Vault built-in roles',
          'Test access from each consumer identity before deleting the legacy access policy',
        ] },
        { approach: 'az CLI — enable purge protection (one-way).', mechanism: 'cli', steps: ['az keyvault update --name <vault> --enable-purge-protection true'] },
      ],
    },
    nist_controls: ['ac-3', 'sc-12'],
    cross_ksi_dependencies: [
      { ksi_id: 'KSI-IAM-ELP', relationship: 'shares-remediation', note: 'RBAC authorization on Key Vault is the same least-privilege story IAM-ELP enforces tenant-wide.' },
    ],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
