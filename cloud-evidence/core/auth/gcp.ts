/**
 * GCP client factory.
 *
 * Phase 1 uses Application Default Credentials. The runner is expected to
 * have run `gcloud auth application-default login` (or be in a GCE/GKE/CR
 * environment where ADC is auto-populated).
 *
 * GCP cannot be Proxy-wrapped as uniformly as AWS — the surface is too
 * varied (googleapis omnibus vs per-service @google-cloud packages). We
 * enforce read-only by convention (only `.get`, `.list`, `.search`,
 * `.export*`, and equivalent methods are called from collectors) AND by
 * mandating that the runner's ADC principal hold only viewer/securityReviewer
 * roles. See README for the role list.
 */
import { GoogleAuth } from 'google-auth-library';
import { google } from 'googleapis';
import { wrapGcpClient } from '../readonly-guardrail-gcp.ts';

const GCP_GUARDRAIL_DISABLED = process.env.CLOUD_EVIDENCE_DISABLE_GCP_GUARDRAIL === '1';

/** Verify ADC works and capture the principal email. */
export async function whoAmIGcp(): Promise<{ principal: string }> {
  const auth = new GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/cloud-platform.read-only'],
  });
  const client = await auth.getClient();
  // getCredentials() returns { client_email, ... } for SAs, or unavailable for user creds.
  // Fall back to the userinfo endpoint via the OAuth client.
  const creds: any = (client as any).credentials ?? {};
  const principal = creds.client_email
    ?? (await (async () => {
      try {
        const userinfo = await new google.auth.OAuth2().getTokenInfo(
          (await client.getAccessToken()).token ?? '',
        );
        return userinfo.email ?? '<unknown>';
      } catch {
        return '<unknown>';
      }
    })());
  return { principal };
}

/**
 * Construct an authed googleapis client for a given service + version,
 * using the read-only OAuth scope.
 *
 * The returned client is wrapped in a Proxy guardrail (core/readonly-guardrail-gcp.ts)
 * that throws on any method whose name classifies as a write operation
 * (create*, update*, delete*, set*, patch*, etc.). This is in addition to
 * the read-only OAuth scope above and the read-only IAM roles the runner's
 * principal must have.
 *
 * Disable with CLOUD_EVIDENCE_DISABLE_GCP_GUARDRAIL=1 only for debugging.
 */
export async function googleClient<T extends object = any>(
  apiName: string,
  version: string,
): Promise<T> {
  const auth = new GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/cloud-platform.read-only'],
  });
  const authClient = await auth.getClient();
  // @ts-ignore — google.{api}({version, auth}) is the documented call shape
  const raw = google[apiName]({ version, auth: authClient }) as T;
  return GCP_GUARDRAIL_DISABLED ? raw : wrapGcpClient(raw, `gcp:${apiName}/${version}`);
}

/**
 * Wrap any GCP client (e.g. one from `@google-cloud/asset`) in the read-only
 * guardrail. Useful when a collector instantiates a per-service client
 * directly (not through googleClient()).
 */
export function guardGcp<T extends object>(client: T, name = 'gcp-client'): T {
  return GCP_GUARDRAIL_DISABLED ? client : wrapGcpClient(client, name);
}
