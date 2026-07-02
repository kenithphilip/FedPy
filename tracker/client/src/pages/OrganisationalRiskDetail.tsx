import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { riskRegisterApi, type OrganisationalRisk, type AuditRow } from '../lib/risk-register-api';
import { canCloseOrganisationalRisk, MIN_CLOSURE_REASON } from '../lib/risk-register-view';

/**
 * LOOP-B.B5 — Organisational risk detail + close-out. iso/ao/admin may close an
 * open risk with a ≥20-char reason; the closure is recorded in the audit log.
 * Closed risks stay in the register (XLSX export includes open + closed) but are
 * hidden by default in the collector's active RA-3 aggregation.
 */
export function OrganisationalRiskDetail() {
  const { uuid = '' } = useParams();
  const nav = useNavigate();
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [risk, setRisk] = useState<OrganisationalRisk | null>(null);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    setError(null);
    try {
      const r = await riskRegisterApi.detail(uuid);
      setRisk(r.organisational_risk);
      setAudit(r.audit);
    } catch (e: any) { setError(e.message); }
  };
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [uuid]);

  async function close() {
    setError(null); setBusy(true);
    try { await riskRegisterApi.close(uuid, reason.trim()); setReason(''); await reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  if (!risk) return <div className="muted">{error ? <span className="alert error">{error}</span> : 'Loading…'}</div>;

  return (
    <div>
      <button className="ghost" onClick={() => nav('/risk-register')}>← Back to register</button>
      <h1>{risk.title}</h1>
      {error && <div className="alert error">{error}</div>}
      <table>
        <tbody>
          <tr><th>Status</th><td>{risk.status}</td></tr>
          <tr><th>Category</th><td>{risk.category}</td></tr>
          <tr><th>Likelihood × Impact</th><td>{risk.likelihood} × {risk.impact}</td></tr>
          <tr><th>Inherent risk</th><td>{risk.inherent_risk}</td></tr>
          <tr><th>Residual risk</th><td>{risk.residual_risk}</td></tr>
          <tr><th>Treatment</th><td>{risk.treatment}</td></tr>
          <tr><th>Owner</th><td>{risk.owner}</td></tr>
          <tr><th>Review date</th><td>{risk.review_date.slice(0, 10)}</td></tr>
          <tr><th>NIST controls</th><td>{risk.nist_control_ids.map((n) => <code key={n} style={{ marginRight: 4 }}>{n}</code>)}</td></tr>
          <tr><th>Description</th><td>{risk.description}</td></tr>
          {risk.status === 'closed' && <tr><th>Closure reason</th><td>{risk.closure_reason}</td></tr>}
        </tbody>
      </table>

      {canCloseOrganisationalRisk(role, risk.status) && (
        <div style={{ marginTop: 16 }}>
          <h3>Close this risk</h3>
          <textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={`Closure reason (≥ ${MIN_CLOSURE_REASON} chars)`} style={{ width: '100%', maxWidth: 640 }} />
          <div style={{ marginTop: 8 }}>
            <button className="primary" onClick={close} disabled={busy || reason.trim().length < MIN_CLOSURE_REASON}>Close risk</button>
          </div>
        </div>
      )}

      <h3 style={{ marginTop: 20 }}>Audit trail</h3>
      <table>
        <thead><tr><th>When</th><th>Field</th><th>Old</th><th>New</th></tr></thead>
        <tbody>
          {audit.length === 0 && <tr><td colSpan={4} className="muted">No audit entries.</td></tr>}
          {audit.map((a, i) => (
            <tr key={i}><td>{a.changed_at}</td><td>{a.field}</td><td>{a.old_value ?? ''}</td><td>{a.new_value ?? ''}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
