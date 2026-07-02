import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { riskRegisterApi } from '../lib/risk-register-api';
import {
  MIN_DESCRIPTION,
  RISK_BANDS, RISK_CATEGORIES, RISK_TREATMENTS,
  canSubmitOrganisationalRiskForm, descriptionRemaining, suggestedInherent, validateOrganisationalRiskForm,
  type OrganisationalRiskFormState, type RiskBand, type RiskTreatment, type OrganisationalRiskCategory,
} from '../lib/risk-register-view';

/**
 * LOOP-B.B5 — Create an organisational risk. NIST SP 800-30 likelihood/impact
 * dropdowns; the inherent band is computed server-side from Table I-2 (shown here
 * as a live "Suggested inherent" hint per Q5). Residual is operator-set. NIST ids
 * validate against the catalog server-side; review date must be ≥30 days out.
 */
export function OrganisationalRiskCreate() {
  const nav = useNavigate();
  const [s, setS] = useState<OrganisationalRiskFormState>({
    title: '', description: '', category: '', likelihood: '', impact: '', residual_risk: '', treatment: '', review_date: '',
  });
  const [nistText, setNistText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (patch: Partial<OrganisationalRiskFormState>) => setS((prev) => ({ ...prev, ...patch }));
  const problems = validateOrganisationalRiskForm(s);
  const remaining = descriptionRemaining(s.description);
  const inherent = suggestedInherent(s);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      const nistIds = nistText.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
      const { organisational_risk } = await riskRegisterApi.create({
        title: s.title.trim(),
        description: s.description,
        category: s.category as OrganisationalRiskCategory,
        likelihood: s.likelihood as RiskBand,
        impact: s.impact as RiskBand,
        residual_risk: s.residual_risk as RiskBand,
        treatment: s.treatment as RiskTreatment,
        review_date: new Date(s.review_date).toISOString(),
        nist_control_ids: nistIds.length ? nistIds : undefined,
      });
      nav(`/risk-register/organisational/${organisational_risk.uuid}`);
    } catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <h1>New organisational risk</h1>
      {error && <div className="alert error">{error}</div>}
      <form onSubmit={submit} style={{ maxWidth: 640 }}>
        <label>Title (5–200 chars)<input value={s.title} onChange={(e) => set({ title: e.target.value })} /></label>
        <label>
          Description{' '}
          <span className="muted" style={{ color: remaining > 0 ? 'crimson' : undefined }}>
            ({s.description.length}/{MIN_DESCRIPTION}{remaining > 0 ? `, ${remaining} more` : ' ✓'})
          </span>
          <textarea rows={5} value={s.description} onChange={(e) => set({ description: e.target.value })} />
        </label>
        <label>Category
          <select value={s.category} onChange={(e) => set({ category: e.target.value as OrganisationalRiskCategory })}>
            <option value="">— select —</option>
            {RISK_CATEGORIES.map((cat) => <option key={cat} value={cat}>{cat}</option>)}
          </select>
        </label>
        <div style={{ display: 'flex', gap: 12 }}>
          <label>Likelihood (NIST 800-30)
            <select value={s.likelihood} onChange={(e) => set({ likelihood: e.target.value as RiskBand })}>
              <option value="">—</option>
              {RISK_BANDS.map((b) => <option key={b} value={b}>{b}</option>)}
            </select>
          </label>
          <label>Impact (NIST 800-30)
            <select value={s.impact} onChange={(e) => set({ impact: e.target.value as RiskBand })}>
              <option value="">—</option>
              {RISK_BANDS.map((b) => <option key={b} value={b}>{b}</option>)}
            </select>
          </label>
        </div>
        {inherent && <p className="muted">Suggested inherent (NIST 800-30 Table I-2): <code>{inherent}</code></p>}
        <label>Residual risk (after treatment / compensating controls)
          <select value={s.residual_risk} onChange={(e) => set({ residual_risk: e.target.value as RiskBand })}>
            <option value="">—</option>
            {RISK_BANDS.map((b) => <option key={b} value={b}>{b}</option>)}
          </select>
        </label>
        <label>Treatment (ISO 31000)
          <select value={s.treatment} onChange={(e) => set({ treatment: e.target.value as RiskTreatment })}>
            <option value="">—</option>
            {RISK_TREATMENTS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>Review date (≥ 30 days out)
          <input type="date" value={s.review_date.slice(0, 10)} onChange={(e) => set({ review_date: e.target.value })} />
        </label>
        <label>NIST 800-53 control ids (optional; comma / space separated)
          <input value={nistText} onChange={(e) => setNistText(e.target.value)} placeholder="SA-9, SR-3" />
        </label>

        {problems.length > 0 && <ul className="muted" style={{ fontSize: 12 }}>{problems.map((p, i) => <li key={i}>{p}</li>)}</ul>}
        <div style={{ marginTop: 12 }}>
          <button className="primary" type="submit" disabled={busy || !canSubmitOrganisationalRiskForm(s)}>Create risk</button>
          <button className="ghost" type="button" onClick={() => nav('/risk-register')}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
