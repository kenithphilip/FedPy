import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { riskAcceptanceApi } from '../lib/risk-acceptance-api';
import {
  ACCEPTANCE_TYPES,
  MIN_JUSTIFICATION,
  canSubmitCreateForm,
  justificationRemaining,
  validateCreateForm,
  type AcceptanceType,
  type CreateFormState,
} from '../lib/risk-acceptance-view';

/**
 * LOOP-B.B3 — Create a pending risk acceptance. Client-side validation mirrors
 * the server (min-100-char justification, 7–365 day expiration, deviation-request
 * requires a compensating control). The server re-validates + signs on POST.
 */
export function RiskAcceptanceCreate() {
  const nav = useNavigate();
  const [s, setS] = useState<CreateFormState>({
    finding_uuid: '', poam_item_uuid: '', ksi_id: '', rule: '', provider: 'aws',
    expiration_date: '', business_justification: '', acceptance_type: 'risk-adjustment', compensating_control_uuids: [],
  });
  const [ccText, setCcText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (patch: Partial<CreateFormState>) => setS((prev) => ({ ...prev, ...patch }));
  const problems = validateCreateForm(s);
  const remaining = justificationRemaining(s.business_justification);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      const { acceptance } = await riskAcceptanceApi.create({
        finding_uuid: s.finding_uuid.trim(),
        poam_item_uuid: s.poam_item_uuid.trim(),
        ksi_id: s.ksi_id.trim(),
        rule: s.rule.trim(),
        provider: s.provider.trim(),
        expiration_date: new Date(s.expiration_date).toISOString(),
        business_justification: s.business_justification,
        acceptance_type: s.acceptance_type,
        compensating_control_uuids: s.compensating_control_uuids,
      });
      nav(`/risk-acceptance/${acceptance.uuid}`);
    } catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  function syncCcs(text: string) {
    setCcText(text);
    set({ compensating_control_uuids: text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean) });
  }

  return (
    <div>
      <h1>New risk acceptance</h1>
      {error && <div className="alert error">{error}</div>}
      <form onSubmit={submit} style={{ maxWidth: 640 }}>
        <label>Finding UUID<input value={s.finding_uuid} onChange={(e) => set({ finding_uuid: e.target.value })} /></label>
        <label>POA&amp;M item UUID<input value={s.poam_item_uuid} onChange={(e) => set({ poam_item_uuid: e.target.value })} /></label>
        <label>KSI<input value={s.ksi_id} onChange={(e) => set({ ksi_id: e.target.value })} placeholder="KSI-IAM-MFA" /></label>
        <label>Rule<input value={s.rule} onChange={(e) => set({ rule: e.target.value })} placeholder="iam-mfa-aws-root" /></label>
        <label>Provider
          <select value={s.provider} onChange={(e) => set({ provider: e.target.value })}>
            <option value="aws">aws</option><option value="gcp">gcp</option><option value="azure">azure</option>
          </select>
        </label>
        <label>Acceptance type
          <select value={s.acceptance_type} onChange={(e) => set({ acceptance_type: e.target.value as AcceptanceType })}>
            {ACCEPTANCE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>Expiration date
          <input type="date" value={s.expiration_date.slice(0, 10)} onChange={(e) => set({ expiration_date: e.target.value })} />
        </label>
        <label>
          Business justification{' '}
          <span className="muted" style={{ color: remaining > 0 ? 'crimson' : undefined }}>
            ({s.business_justification.length}/{MIN_JUSTIFICATION}{remaining > 0 ? `, ${remaining} more` : ' ✓'})
          </span>
          <textarea rows={5} value={s.business_justification} onChange={(e) => set({ business_justification: e.target.value })} />
        </label>
        <label>
          Compensating control UUIDs (comma / space separated{s.acceptance_type === 'deviation-request' ? ', required' : ', optional'})
          <input value={ccText} onChange={(e) => syncCcs(e.target.value)} placeholder="cc-uuid-1, cc-uuid-2" />
        </label>
        <p className="muted" style={{ fontSize: 12 }}>Compensating-control UUIDs resolve to the B.B4 registry once it ships; until then paste UUIDs directly.</p>

        {problems.length > 0 && (
          <ul className="muted" style={{ fontSize: 12 }}>{problems.map((p, i) => <li key={i}>{p}</li>)}</ul>
        )}
        <div style={{ marginTop: 12 }}>
          <button className="primary" type="submit" disabled={busy || !canSubmitCreateForm(s)}>Create pending acceptance</button>
          <button className="ghost" type="button" onClick={() => nav('/risk-acceptance')}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
