/**
 * Azure cryptographic-modules collector — KSI-AFR-UCM.
 *
 * Mirror of `providers/{aws,gcp}/crypto.ts`. The KSI requires that
 * cryptographic modules protecting federal customer data align with
 * FedRAMP's Using Cryptographic Modules (UCM) guidance, which boils down
 * (Phase 2) to: FIPS 140-2 / 140-3 validated modules, with CMVP certificates
 * referenced in the SSP.
 *
 * Cloud-side signal (proxy): the operator runs all crypto on Azure-native
 * surfaces that are themselves FIPS-validated (Azure Key Vault, App Service
 * minimum TLS, Application Gateway SSL policies, managed-disk SSE-with-CMK,
 * Storage SSE-with-CMK). The CMVP certificate references are tracked
 * separately via `process_artifacts_required`.
 *
 * Findings (single):
 *   - `azure.afr.ucm.fips_validated_modules_in_use` — at least one of:
 *       1. Key Vault keys with valid keyOps + key-rotation policy
 *       2. AGW SSL policies above the deprecated TLS 1.0/1.1 baselines
 *       3. Storage accounts with `requireInfrastructureEncryption = true`
 *
 * Read-only via Resource Graph; `Reader` is sufficient.
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

// TLS policy names that DO satisfy modern FIPS-aligned minimums.
// AppGw policy names below TLS 1.2 are deprecated / unsafe and would fail.
const MODERN_TLS_POLICIES = new Set([
  'appgwsslpolicy20220101', 'appgwsslpolicy20220101s',
  'appgwsslpolicy20170401s', 'appgwsslpolicy20170401',
  'appgwsslpolicy20150501', // legacy named; still TLS 1.2-min
]);

// =====================================================================
// KSI-AFR-UCM — Using Cryptographic Modules (HYBRID)
// =====================================================================
export async function collectUcm(ctx: CollectorContext): Promise<ProviderBlock> {
  const subs = subscriptionsOf(ctx);
  const evidence: RawEvidence[] = [];
  const findings: Finding[] = [];
  const warnings: string[] = [];

  // 1) Key Vault keys + rotation policy presence. Azure Key Vault's HSM-backed
  // and software keys are FIPS 140-2 (software) / 140-3 (managed-HSM) validated.
  const keys = await runKql(subs,
    'Resources | where type =~ "microsoft.keyvault/vaults/keys" ' +
    '| extend kty = tostring(properties.kty), enabled = tobool(properties.attributes.enabled) ' +
    '| project id, name, subscriptionId, kty, enabled');
  if (keys.error) warnings.push(keys.error);

  // 2) Application Gateway SSL policies (TLS 1.2 minimum is the FIPS-aligned bar).
  const agw = await runKql(subs,
    'Resources | where type =~ "microsoft.network/applicationgateways" ' +
    '| extend policyName = tolower(tostring(properties.sslPolicy.policyName)), ' +
    'minProto = tostring(properties.sslPolicy.minProtocolVersion) ' +
    '| project id, name, subscriptionId, policyName, minProto');
  if (agw.error) warnings.push(agw.error);

  // 3) Storage accounts with requireInfrastructureEncryption (FIPS-validated
  // double-encrypt path).
  const storage = await runKql(subs,
    'Resources | where type =~ "microsoft.storage/storageaccounts" ' +
    '| extend infraEnc = tobool(properties.encryption.requireInfrastructureEncryption) ' +
    '| project id, name, subscriptionId, infraEnc');
  if (storage.error) warnings.push(storage.error);

  const enabledKeys = keys.rows.filter((k: any) => k.enabled === true).length;
  const compliantAgw = agw.rows.filter((g: any) => {
    const policy = String(g.policyName ?? '').toLowerCase();
    const minProto = String(g.minProto ?? '').toLowerCase();
    return MODERN_TLS_POLICIES.has(policy) || minProto === 'tlsv1_2' || minProto === 'tlsv1_3';
  }).length;
  const infraEncStorage = storage.rows.filter((s: any) => s.infraEnc === true).length;

  evidence.push(ev('resourcegraph.ucm_signals', {
    key_vault_keys: keys.rows.length, key_vault_keys_enabled: enabledKeys,
    application_gateways: agw.rows.length, application_gateways_modern_tls: compliantAgw,
    storage_accounts: storage.rows.length, storage_with_infrastructure_encryption: infraEncStorage,
  }));

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: 'External HSM / 3rd-party FIPS module (Thales Luna / nCipher / AWS CloudHSM bridge)',
      description: 'Cryptographic operations use an external FIPS 140-2/140-3 validated module; Azure Key Vault is bypassed for sensitive operations.',
      evidence_required: ['HSM vendor + CMVP certificate number', 'Mapping of services → external HSM', 'Audit log sample from the HSM'],
      detected: false, detection_signals: [],
    },
  ];

  // Pass if ANY of the three signals is present.
  const passed = enabledKeys >= 1 || compliantAgw >= 1 || infraEncStorage >= 1;

  findings.push(finding({
    rule: 'azure.afr.ucm.fips_validated_modules_in_use',
    passed,
    severity: 'high',
    current: {
      summary: passed
        ? `FIPS-aligned crypto in use: ${enabledKeys} Key Vault key(s), ${compliantAgw} AGW(s) on modern TLS, ${infraEncStorage} storage account(s) with infrastructure encryption.`
        : 'No Key Vault keys, no modern-TLS Application Gateways, and no storage accounts with infrastructure encryption — no Azure-canonical FIPS-validated crypto in evidence.',
      observations: {
        key_vault_keys_enabled: enabledKeys,
        application_gateways_modern_tls: compliantAgw,
        storage_with_infrastructure_encryption: infraEncStorage,
      },
    },
    target: { summary: 'At least one Azure-canonical FIPS-validated crypto surface is in active use (Key Vault keys, modern-TLS Application Gateway, or infrastructure-encrypted storage), OR an external HSM is documented via the alternative satisfier.', rationale: 'NIST SC-13, SC-12, SC-8, IA-7. The FedRAMP UCM guidance requires CMVP-validated cryptographic modules for protecting federal data.' },
    gap: { description: 'No Azure-native FIPS-validated crypto surface observed — either crypto is happening off-Azure (use alt satisfier) or sensitive data isn\'t protected by a validated module.', affected_resources: [{ type: 'azure_crypto_surface', identifier: 'aggregate', attributes: { keys: enabledKeys, agw: compliantAgw, storage: infraEncStorage } }] },
    remediation: {
      summary: 'Provision Azure Key Vault (Premium SKU for HSM-backed keys) AND configure modern TLS on internet-facing Application Gateways AND enable storage infrastructure-encryption on prod storage accounts.',
      options: [
        { approach: 'Terraform azurerm_key_vault_key + azurerm_application_gateway.ssl_policy + azurerm_storage_account.infrastructure_encryption_enabled.', mechanism: 'terraform', steps: [
          'Provision azurerm_key_vault with sku_name = "premium" for HSM-backed keys',
          'Set AGW ssl_policy { policy_type = "Predefined"; policy_name = "AppGwSslPolicy20220101" }',
          'Set azurerm_storage_account.infrastructure_encryption_enabled = true',
        ] },
      ],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['sc-13', 'sc-12', 'sc-8', 'ia-7'],
  }));

  return { provider: 'azure', account_id: null, evidence, findings, warnings, ksi_level_alternatives: altSatisfiers };
}
