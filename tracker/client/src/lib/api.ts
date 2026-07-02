export interface User {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'member';
}

/** Read the CSRF cookie set by the server at login/signup. */
function readCsrfCookie(): string | null {
  const match = document.cookie.match(/(?:^|; )fr20x_csrf=([^;]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

/**
 * Custom error carrying the HTTP status code so callers can distinguish
 *   401 (re-login required), 403 (insufficient role), 429 (rate-limited),
 *   5xx (server fault) without parsing the message string.
 * Also carries the server's `error` code if it returned JSON.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string | null,
    message: string,
    public readonly retryAfterSec?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(init.headers as Record<string, string> ?? {}),
  };
  if (UNSAFE_METHODS.has(method)) {
    const csrf = readCsrfCookie();
    if (csrf) headers['X-CSRF-Token'] = csrf;
    else console.warn(`[api] No CSRF cookie present for ${method} ${path}; the request will likely fail with 403 csrf_missing. The user may need to log in again.`);
  }

  // Distinguish network failures from HTTP errors so the UI can show
  // "offline / network error" vs "server returned X".
  let res: Response;
  try {
    res = await fetch(path, {
      credentials: 'same-origin',
      ...init,
      method,
      headers,
    });
  } catch (e: any) {
    // fetch() only throws on network-layer failures (offline, DNS, CORS).
    throw new ApiError(0, 'network_error', `Network error contacting ${path}: ${e?.message ?? e}. Check your connection.`);
  }
  if (!res.ok) {
    let code: string | null = null;
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      code = typeof j?.error === 'string' ? j.error : null;
      msg = j?.message ?? j?.error ?? msg;
    } catch {}
    const retryAfterHeader = res.headers.get('retry-after');
    const retryAfterSec = retryAfterHeader ? Number(retryAfterHeader) : undefined;
    throw new ApiError(res.status, code, msg, Number.isFinite(retryAfterSec) ? retryAfterSec : undefined);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  // auth
  bootstrap: () => request<{ needsBootstrap: boolean }>('/api/auth/bootstrap'),
  me: () => request<{ user: User }>('/api/auth/me'),
  login: (email: string, password: string) =>
    request<{ user: User; requires_2fa?: boolean }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  signup: (email: string, name: string, password: string) =>
    request<{ user: User }>('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email, name, password }) }),
  logout: () => request<{ ok: true }>('/api/auth/logout', { method: 'POST' }),

  // meta + reference
  meta: () => request<{ meta: Record<string, string> }>('/api/meta'),
  processes: () => request<{ processes: any[] }>('/api/processes'),
  processDetail: (id: string) => request<{ process: any; labels: any[] }>(`/api/processes/${id}`),
  ksiDomains: () => request<{ domains: any[] }>('/api/ksi-domains'),
  definitions: () => request<{ definitions: any[] }>('/api/definitions'),
  users: () => request<{ users: User[] }>('/api/users'),

  // requirements / indicators
  requirements: (params: Record<string, string | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
    return request<{ requirements: any[] }>(`/api/requirements${qs.toString() ? '?' + qs : ''}`);
  },
  requirementDetail: (id: string) =>
    request<{ requirement: any; history: any[] }>(`/api/requirements/${id}`),
  indicators: (params: Record<string, string | undefined> = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v) qs.set(k, v);
    return request<{ indicators: any[] }>(`/api/indicators${qs.toString() ? '?' + qs : ''}`);
  },
  indicatorDetail: (id: string) =>
    request<{ indicator: any; history: any[] }>(`/api/indicators/${id}`),

  // state
  patchItem: (type: 'requirement' | 'indicator', id: string, patch: any) =>
    request<{ ok: true; state: any }>(`/api/items/${type}/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  // dashboard
  dashboard: () => request<{ overall: any; by_process: any[]; by_domain: any[]; next_up: any[] }>('/api/dashboard'),
  crosswalk: () => request<{ controls: any[] }>('/api/crosswalk'),

  // collector runs (cloud-evidence telemetry)
  collectorLatest: () => request<{ run: any | null }>('/api/collector-runs/latest'),
  collectorList: () => request<{ runs: any[] }>('/api/collector-runs'),

  // API tokens (admin only)
  tokensList: () => request<{ tokens: any[] }>('/api/auth/tokens'),
  tokenCreate: (name: string, scope: string, ttl_days?: number) =>
    request<{ id: number; name: string; scope: string; token: string; warning: string }>('/api/auth/tokens', {
      method: 'POST', body: JSON.stringify({ name, scope, ttl_days }),
    }),
  tokenRevoke: (id: number) =>
    request<{ ok: true }>(`/api/auth/tokens/${id}/revoke`, { method: 'POST' }),

  // 2FA
  twoFaStatus: () => request<{ enrolled: boolean; required: boolean; backup_codes_remaining: number }>('/api/2fa/status'),
  twoFaEnroll: () => request<{ secret_b32: string; otpauth_uri: string; backup_codes: string[] }>('/api/2fa/enroll', { method: 'POST' }),
  twoFaComplete: (code: string) => request<{ enrolled: boolean }>('/api/2fa/complete', { method: 'POST', body: JSON.stringify({ code }) }),
  twoFaVerify: (code: string) => request<{ ok: boolean; via: 'totp' | 'backup' }>('/api/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  twoFaDisable: (password: string) => request<{ disabled: boolean }>('/api/2fa/disable', { method: 'POST', body: JSON.stringify({ password }) }),

  // RBAC admin
  usersList: () => request<{ users: User[] }>('/api/users'),
  userSetRole: (userId: number, role: string) =>
    request<{ ok: true }>(`/api/users/${userId}/role`, { method: 'PATCH', body: JSON.stringify({ role }) }),
  userDomains: (userId: number) =>
    request<{ domains: string[] }>(`/api/users/${userId}/domains`),
  userAssignDomain: (userId: number, domain: string) =>
    request<{ ok: true }>(`/api/users/${userId}/domains`, { method: 'POST', body: JSON.stringify({ domain }) }),
  userUnassignDomain: (userId: number, domain: string) =>
    request<{ ok: true }>(`/api/users/${userId}/domains/${domain}`, { method: 'DELETE' }),

  // Audit log search
  auditSearch: (params: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, String(v));
    return request<{ rows: any[]; total: number; limit: number; offset: number }>(`/api/audit?${q.toString()}`);
  },
  auditFacets: () => request<{ actions: string[]; item_types: string[]; actors: any[] }>('/api/audit/facets'),
  auditCsvUrl: (params: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') q.set(k, String(v));
    return `/api/audit/csv?${q.toString()}`;
  },

  // File attachments
  attachmentsList: (itemId: string, itemType: string) =>
    request<{ attachments: Attachment[] }>(`/api/items/${encodeURIComponent(itemId)}/${itemType}/attachments`),
  attachmentDelete: (itemId: string, itemType: string, id: number) =>
    request<{ ok: true }>(`/api/items/${encodeURIComponent(itemId)}/${itemType}/attachments/${id}`, { method: 'DELETE' }),
  attachmentUpload: (itemId: string, itemType: string, file: File) =>
    uploadFile(`/api/items/${encodeURIComponent(itemId)}/${itemType}/attachments`, file),
  attachmentDownloadUrl: (id: number) => `/api/attachments/${id}`,
};

export interface Attachment {
  id: number;
  filename: string;
  content_type: string;
  bytes: number;
  sha256: string;
  uploaded_at: string;
  uploaded_by_email?: string | null;
  uploaded_by_name?: string | null;
}

export interface AttachmentUploadResult {
  id: number;
  filename: string;
  content_type: string;
  bytes: number;
  sha256: string;
  /** True when the original filename exceeded the server limit and was truncated. */
  filename_truncated?: boolean;
}

/**
 * Multipart upload helper. Unlike `request()` we must NOT set content-type —
 * the browser sets the multipart boundary itself — but we still attach the
 * CSRF header and reuse the same ApiError translation.
 */
async function uploadFile(path: string, file: File): Promise<AttachmentUploadResult> {
  const fd = new FormData();
  fd.append('file', file);
  const headers: Record<string, string> = {};
  const csrf = readCsrfCookie();
  if (csrf) headers['X-CSRF-Token'] = csrf;

  let res: Response;
  try {
    res = await fetch(path, { method: 'POST', credentials: 'same-origin', headers, body: fd });
  } catch (e: any) {
    throw new ApiError(0, 'network_error', `Network error uploading to ${path}: ${e?.message ?? e}. Check your connection.`);
  }
  if (!res.ok) {
    let code: string | null = null;
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      code = typeof j?.error === 'string' ? j.error : null;
      msg = j?.message ?? j?.error ?? msg;
    } catch {}
    throw new ApiError(res.status, code, msg);
  }
  return res.json() as Promise<AttachmentUploadResult>;
}
