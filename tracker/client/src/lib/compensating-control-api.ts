/**
 * LOOP-B.B4 — Typed fetch client for the compensating-controls registry API.
 * Reuses the shared request() helper (CSRF header + ApiError translation).
 */
import { request } from './api';
import type { ControlStatus } from './compensating-control-view';

export interface CompensatingControl {
  id: number;
  uuid: string;
  title: string;
  description: string;
  nist_control_ids: string[];
  implemented_by_user_id: number;
  implemented_at: string;
  signed_off_by_user_id: number | null;
  signed_off_at: string | null;
  expiration_date: string | null;
  evidence_url: string | null;
  evidence_sha256: string | null;
  status: ControlStatus;
  signature: string;
  signing_key_id: string;
  activation_signature: string | null;
  activation_signing_key_id: string | null;
  retired_at: string | null;
  retired_by_user_id: number | null;
  retirement_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateCompensatingControlBody {
  title: string;
  description: string;
  nist_control_ids: string[];
  evidence_url?: string;
  expiration_date?: string;
}

export interface AuditRow {
  user_id: number | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  changed_at: string;
}

export interface LinkedAcceptance {
  uuid: string;
  status: string;
  ksi_id: string;
  rule: string;
}

export interface ControlListResult {
  items: CompensatingControl[];
  public_key: string;
  catalog_version: string;
  total: number;
  limit: number;
  offset: number;
}

export const compensatingControlApi = {
  list: (params: { status?: string; nist_control_id?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') qs.set(k, String(v));
    return request<ControlListResult>(`/api/compensating-controls${qs.toString() ? '?' + qs : ''}`);
  },
  detail: (uuid: string) =>
    request<{ compensating_control: CompensatingControl; linked_acceptances: LinkedAcceptance[]; audit: AuditRow[]; public_key: string }>(
      `/api/compensating-controls/${uuid}`,
    ),
  verify: (uuid: string) =>
    request<{ valid: boolean; activation_valid: boolean | null; signing_key_id: string }>(`/api/compensating-controls/${uuid}/verify`),
  create: (body: CreateCompensatingControlBody) =>
    request<{ compensating_control: CompensatingControl; catalog_version: string }>('/api/compensating-controls', {
      method: 'POST', body: JSON.stringify(body),
    }),
  activate: (uuid: string) =>
    request<{ compensating_control: CompensatingControl }>(`/api/compensating-controls/${uuid}/activate`, { method: 'POST', body: '{}' }),
  retire: (uuid: string, retirement_reason: string) =>
    request<{ compensating_control: CompensatingControl }>(`/api/compensating-controls/${uuid}/retire`, {
      method: 'POST', body: JSON.stringify({ retirement_reason }),
    }),
};
