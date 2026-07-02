/**
 * LOOP-B.B5 — Typed fetch client for the Central Risk Register API.
 * Reuses the shared request() helper (CSRF header + ApiError translation).
 */
import { request } from './api';
import type { RiskBand, RiskBandOrMarker, RiskTreatment, OrganisationalRiskCategory } from './risk-register-view';

export interface OrganisationalRisk {
  id: number;
  uuid: string;
  title: string;
  description: string;
  category: OrganisationalRiskCategory;
  likelihood: RiskBand;
  impact: RiskBand;
  inherent_risk: RiskBand;
  residual_risk: RiskBand;
  treatment: RiskTreatment;
  owner_user_id: number;
  owner: string;
  review_date: string;
  nist_control_ids: string[];
  compensating_control_uuids: string[];
  status: 'open' | 'closed';
  closed_at: string | null;
  closed_by_user_id: number | null;
  closure_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateOrganisationalRiskBody {
  title: string;
  description: string;
  category: OrganisationalRiskCategory;
  likelihood: RiskBand;
  impact: RiskBand;
  residual_risk: RiskBand;
  treatment: RiskTreatment;
  review_date: string;
  owner_user_id?: number;
  nist_control_ids?: string[];
  compensating_control_uuids?: string[];
}

export interface AuditRow {
  user_id: number | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  changed_at: string;
}

export interface RegisterEntry {
  uuid: string;
  source: string;
  title: string;
  category: string;
  likelihood: RiskBandOrMarker;
  impact: RiskBandOrMarker;
  inherent_risk: RiskBandOrMarker;
  residual_risk: RiskBandOrMarker;
  treatment: string;
  owner: string;
  review_date: string;
  status: string;
  poam_item_uuid?: string | null;
  acceptance_uuid?: string | null;
  compensating_control_uuids?: string[] | null;
  nist_control_ids?: string[] | null;
  description: string;
}

export interface RegisterResult {
  entries: RegisterEntry[];
  summary: { entries_total: number; by_source: Record<string, number>; high_inherent_count: number };
}

export const riskRegisterApi = {
  listOrganisational: (params: { status?: string; category?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') qs.set(k, String(v));
    return request<{ items: OrganisationalRisk[]; total: number; limit: number; offset: number; catalog_version: string }>(
      `/api/organisational-risks${qs.toString() ? '?' + qs : ''}`,
    );
  },
  detail: (uuid: string) =>
    request<{ organisational_risk: OrganisationalRisk; audit: AuditRow[] }>(`/api/organisational-risks/${uuid}`),
  create: (body: CreateOrganisationalRiskBody) =>
    request<{ organisational_risk: OrganisationalRisk; catalog_version: string }>('/api/organisational-risks', {
      method: 'POST', body: JSON.stringify(body),
    }),
  update: (uuid: string, body: CreateOrganisationalRiskBody) =>
    request<{ organisational_risk: OrganisationalRisk }>(`/api/organisational-risks/${uuid}`, {
      method: 'PUT', body: JSON.stringify(body),
    }),
  close: (uuid: string, closure_reason: string) =>
    request<{ organisational_risk: OrganisationalRisk }>(`/api/organisational-risks/${uuid}/close`, {
      method: 'POST', body: JSON.stringify({ closure_reason }),
    }),
  register: () => request<RegisterResult>('/api/risk-register'),
  /** URL for the XLSX export (used as an <a href> download so the browser streams it). */
  exportXlsxUrl: () => '/api/risk-register/export.xlsx',
};
