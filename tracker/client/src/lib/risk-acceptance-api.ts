/**
 * LOOP-B.B3 — Typed fetch client for the risk-acceptance workflow API.
 * Reuses the shared request() helper (CSRF header + ApiError translation).
 */
import { request } from './api';
import type { AcceptanceType, AcceptanceStatus } from './risk-acceptance-view';

export interface RiskAcceptance {
  id: number;
  uuid: string;
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  accepted_by_user_id: number;
  accepted_at: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: AcceptanceType;
  status: AcceptanceStatus;
  approved_by_user_id: number | null;
  approved_at: string | null;
  signature: string;
  signing_key_id: string;
  approval_signature: string | null;
  approval_signing_key_id: string | null;
  revoked_at: string | null;
  revoked_by_user_id: number | null;
  revocation_reason: string | null;
  compensating_control_uuids: string[];
}

export interface CreateAcceptanceBody {
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: AcceptanceType;
  compensating_control_uuids: string[];
}

export interface AuditRow {
  user_id: number | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  changed_at: string;
}

export interface AcceptanceListResult {
  items: RiskAcceptance[];
  public_key: string;
  total: number;
  limit: number;
  offset: number;
}

export const riskAcceptanceApi = {
  list: (params: { status?: string; ksi_id?: string; expiring_before?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') qs.set(k, String(v));
    return request<AcceptanceListResult>(`/api/risk-acceptances${qs.toString() ? '?' + qs : ''}`);
  },
  detail: (uuid: string) =>
    request<{ acceptance: RiskAcceptance; audit: AuditRow[] }>(`/api/risk-acceptances/${uuid}`),
  verify: (uuid: string) =>
    request<{ valid: boolean; approval_valid: boolean | null; signing_key_id: string }>(`/api/risk-acceptances/${uuid}/verify`),
  create: (body: CreateAcceptanceBody) =>
    request<{ acceptance: RiskAcceptance }>('/api/risk-acceptances', { method: 'POST', body: JSON.stringify(body) }),
  approve: (uuid: string, approval_notes?: string) =>
    request<{ acceptance: RiskAcceptance }>(`/api/risk-acceptances/${uuid}/approve`, { method: 'POST', body: JSON.stringify({ approval_notes }) }),
  revoke: (uuid: string, revocation_reason: string) =>
    request<{ acceptance: RiskAcceptance }>(`/api/risk-acceptances/${uuid}/revoke`, { method: 'POST', body: JSON.stringify({ revocation_reason }) }),
};
