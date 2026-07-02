import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { riskAcceptanceApi, type RiskAcceptance as RA } from '../lib/risk-acceptance-api';
import { canCreateAcceptance } from '../lib/risk-acceptance-view';

/**
 * LOOP-B.B3 — Risk-acceptance list view. Filterable by status; "New Acceptance"
 * CTA shown only to iso/admin (the server enforces create:risk_acceptance too).
 */
const STATUSES = ['', 'pending', 'approved', 'expired', 'revoked'];

export function RiskAcceptance() {
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [rows, setRows] = useState<RA[]>([]);
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    setError(null); setLoading(true);
    try {
      const r = await riskAcceptanceApi.list({ status: status || undefined });
      setRows(r.items);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [status]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Risk acceptances</h1>
        {canCreateAcceptance(role) && <Link className="primary" to="/risk-acceptance/new">New acceptance</Link>}
      </div>
      <p className="muted">Signed, audited deviation / risk-adjustment decisions (NIST CA-5 / RA-7). Approved, unexpired acceptances flip the matching POA&amp;M risk to <code>deviation-approved</code>.</p>

      <div style={{ margin: '12px 0' }}>
        <label>Status:{' '}
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => <option key={s} value={s}>{s || 'all'}</option>)}
          </select>
        </label>
      </div>

      {error && <div className="alert error">{error}</div>}
      {loading ? <div className="muted">Loading…</div> : (
        <table>
          <thead>
            <tr>
              <th>KSI</th><th>Rule</th><th>Provider</th><th>Status</th><th>Expiration</th><th>Type</th><th>CCs</th><th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={8} className="muted">No acceptances.</td></tr>}
            {rows.map((r) => (
              <tr key={r.uuid}>
                <td>{r.ksi_id}</td>
                <td><code>{r.rule}</code></td>
                <td>{r.provider}</td>
                <td>{r.status}</td>
                <td>{r.expiration_date.slice(0, 10)}</td>
                <td>{r.acceptance_type}</td>
                <td>{r.compensating_control_uuids.length}</td>
                <td><Link to={`/risk-acceptance/${r.uuid}`}>Details</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
