/**
 * Azure client factory.
 *
 * Authentication: `DefaultAzureCredential` from `@azure/identity`, which auto-discovers
 * credentials in this order:
 *   1. EnvironmentCredential        — AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET env vars
 *   2. WorkloadIdentityCredential   — federated workload identity (GitHub OIDC, AKS, …)
 *   3. ManagedIdentityCredential    — running on an Azure resource with MSI
 *   4. AzureCliCredential           — local `az login` session
 *   5. AzureDeveloperCliCredential  — `azd auth login`
 *   6. AzurePowerShellCredential    — `Connect-AzAccount`
 *
 * Read-only enforcement is layered:
 *   - Runner principal MUST hold only read RBAC roles (Reader + Security Reader +
 *     Log Analytics Reader); see IAM-PERMISSIONS-CATALOG.md.
 *   - Every client returned here is wrapped in the Azure read-only guardrail Proxy
 *     (core/readonly-guardrail-azure.ts), which throws on any method whose name
 *     classifies as a write (create/update/delete/begin*-family/patch/set/...).
 *
 * Bypass with CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL=1 only for diagnosing why a
 * legitimate read call is being blocked.
 */
import { DefaultAzureCredential, type TokenCredential } from '@azure/identity';
import { ResourceManagementClient } from '@azure/arm-resources';
import { ResourceGraphClient } from '@azure/arm-resourcegraph';
import { wrapAzureClient } from '../readonly-guardrail-azure.ts';

const AZURE_GUARDRAIL_DISABLED = process.env.CLOUD_EVIDENCE_DISABLE_AZURE_GUARDRAIL === '1';
const ARM_SCOPE = 'https://management.azure.com/.default';

let _credential: TokenCredential | null = null;
function credential(): TokenCredential {
  if (!_credential) _credential = new DefaultAzureCredential();
  return _credential;
}

/** Wrap any Azure SDK client in the read-only guardrail (no-op when disabled by env). */
export function guardAzure<T extends object>(client: T, name = 'azure-client'): T {
  return AZURE_GUARDRAIL_DISABLED ? client : wrapAzureClient(client, name);
}

/** Decode the unsigned payload of a JWT (no signature check — Azure already verified it). */
function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split('.');
  if (parts.length < 2) return null;
  try {
    const raw = Buffer.from(parts[1]!.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(raw);
  } catch { return null; }
}

/**
 * Confirm Azure credentials work (the DefaultAzureCredential chain found at least
 * one method) and report who the runner appears to be. We deliberately avoid an
 * Azure ARM read call here — listing subscriptions is not in @azure/arm-subscriptions
 * v6+, and there's no other one-line "whoami" — so we just acquire an ARM token and
 * decode the JWT for the principal and tenant. Subscription IDs come from config.yaml.
 */
export async function whoAmIAzure(): Promise<{ principal: string; tenantId: string | null; appId: string | null }> {
  const tok = await credential().getToken(ARM_SCOPE);
  if (!tok) throw new Error('Failed to acquire an Azure Resource Manager token (no credential available in the DefaultAzureCredential chain).');
  const p = decodeJwtPayload(tok.token);
  const principal =
    (p?.upn as string | undefined) ??
    (p?.unique_name as string | undefined) ??
    (p?.email as string | undefined) ??
    (p?.preferred_username as string | undefined) ??
    (p?.appid as string | undefined) ??
    (p?.oid as string | undefined) ??
    '<azure-credential>';
  return {
    principal,
    tenantId: (p?.tid as string | undefined) ?? null,
    appId: (p?.appid as string | undefined) ?? null,
  };
}

/**
 * Azure Resource Graph client — the breadth discovery backbone (Azure analog of
 * AWS Config Advanced Query / GCP CAI searchAllResources). The Reader role at the
 * subscription scope grants sufficient access to query resources.
 */
export function resourceGraph(): ResourceGraphClient {
  return guardAzure(new ResourceGraphClient(credential()), 'azure:resource-graph');
}

/** ARM resources client scoped to one subscription (per-resource depth reads). */
export function resources(subscriptionId: string): ResourceManagementClient {
  return guardAzure(new ResourceManagementClient(credential(), subscriptionId), `azure:resources/${subscriptionId}`);
}
