/**
 * Microsoft Graph access for Azure / Entra ID KSI collectors.
 *
 * The Microsoft Graph SDK is heavy (deep transitive tree) and we only need a
 * handful of read-only endpoints, so we do plain REST via fetch — same approach
 * as the JWT-based whoAmIAzure. The `DefaultAzureCredential` chain provides the
 * token; we just request the Graph scope explicitly.
 *
 * Read-only is enforced two ways:
 *   1. **API design.** This module only exposes GET. There is no write path.
 *   2. **RBAC.** The runner principal MUST be granted only `*.Read.All` Graph
 *      permissions (Policy.Read.All, Directory.Read.All, etc.) — see
 *      IAM-PERMISSIONS-CATALOG.md.
 *
 * Bypassing the Azure SDK Proxy guardrail does NOT bypass these — Graph requests
 * are HTTP, not SDK method calls.
 */
import { DefaultAzureCredential, type TokenCredential } from '@azure/identity';

const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';

let _credential: TokenCredential | null = null;
function credential(): TokenCredential {
  if (!_credential) _credential = new DefaultAzureCredential();
  return _credential;
}

let _tokenCache: { token: string; expiresAt: number } | null = null;

async function getGraphToken(): Promise<string> {
  // Reuse a cached token up to 60 s before its expiry (the SDK already handles
  // most refresh, but caching avoids re-running the chain probe per request).
  if (_tokenCache && _tokenCache.expiresAt - Date.now() > 60_000) return _tokenCache.token;
  const tok = await credential().getToken(GRAPH_SCOPE);
  if (!tok) throw new Error('Failed to acquire a Microsoft Graph token (no credential available in the DefaultAzureCredential chain).');
  _tokenCache = { token: tok.token, expiresAt: tok.expiresOnTimestamp };
  return tok.token;
}

/** Pure helper: shape an error from a non-OK fetch response into a readable message. */
function diagnoseGraphError(status: number, statusText: string, body: string, path: string): string {
  const snippet = body.length > 200 ? `${body.slice(0, 200)}…` : body;
  if (status === 401) return `${path}: 401 Unauthorized — token expired or wrong tenant.`;
  if (status === 403) return `${path}: 403 Forbidden — the runner principal lacks the required Graph permission for this endpoint (likely a missing *.Read.All app role).`;
  if (status === 404) return `${path}: 404 Not Found — endpoint not available (resource missing or feature not enabled).`;
  if (status === 429) return `${path}: 429 Too Many Requests — Graph throttled the read; retry with backoff.`;
  return `${path}: ${status} ${statusText} — ${snippet}`;
}

/** GET an arbitrary Graph endpoint; injects the Bearer token. */
async function graphGet(path: string): Promise<{ ok: true; data: any } | { ok: false; error: string }> {
  const url = path.startsWith('http') ? path : `${GRAPH_BASE}${path.startsWith('/') ? '' : '/'}${path}`;
  let token: string;
  try { token = await getGraphToken(); }
  catch (e: any) { return { ok: false, error: `${path}: ${e?.message ?? e}` }; }
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
  } catch (e: any) {
    return { ok: false, error: `${path}: network error — ${e?.message ?? e}` };
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    return { ok: false, error: diagnoseGraphError(res.status, res.statusText, body, path) };
  }
  try {
    const data = await res.json();
    return { ok: true, data };
  } catch (e: any) {
    return { ok: false, error: `${path}: invalid JSON response — ${e?.message ?? e}` };
  }
}

/**
 * GET a Graph endpoint and follow OData @odata.nextLink pagination, returning
 * the concatenated `.value` array. Caps at 100 pages (Graph default page size
 * 100 → 10 000 items) — bump via `maxPages`.
 */
export async function graphFetchAll<T = any>(path: string, opts: { maxPages?: number } = {}): Promise<{ items: T[]; warnings: string[] }> {
  const items: T[] = [];
  const warnings: string[] = [];
  let next: string | null = path;
  let pages = 0;
  const maxPages = opts.maxPages ?? 100;
  while (next) {
    const r: { ok: true; data: any } | { ok: false; error: string } = await graphGet(next);
    if (!r.ok) { warnings.push(r.error); break; }
    const value = Array.isArray(r.data?.value) ? r.data.value : [];
    items.push(...(value as T[]));
    next = (r.data as any)?.['@odata.nextLink'] ?? null;
    if (++pages >= maxPages) {
      warnings.push(`${path}: pagination capped at ${maxPages} pages.`);
      break;
    }
  }
  return { items, warnings };
}

/** GET a single Graph resource (no pagination). Returns the parsed body or null + warning. */
export async function graphFetchOne<T = any>(path: string): Promise<{ data: T | null; warnings: string[] }> {
  const r: { ok: true; data: any } | { ok: false; error: string } = await graphGet(path);
  if (!r.ok) return { data: null, warnings: [r.error] };
  return { data: r.data as T, warnings: [] };
}

/** Exposed for tests so the in-memory token cache can be reset between cases. */
export function _resetTokenCache(): void { _tokenCache = null; }
