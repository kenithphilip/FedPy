import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { compensatingControlApi, type CompensatingControl as CC } from '../lib/compensating-control-api';
import { canCreateControl } from '../lib/compensating-control-view';

/**
 * LOOP-B.B4 — Compensating-controls list view. Filterable by status; "New Control"
 * CTA shown only to iso/admin (the server enforces create:compensating_control too).
 * Active, unexpired controls fill the matching POA&M risk's remediations[] with
 * lifecycle=completed.
 */
const STATUSES = ['', 'draft', 'active', 'retired'];

export function CompensatingControls() {
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [rows, setRows] = useState<CC[]>([]);
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    setError(null); setLoading(true);
    try {
      const r = await compensatingControlApi.list({ status: status || undefined });
      setRows(r.items);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [status]);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Compensating controls</h1>
        {canCreateControl(role) && <Link className="primary" to="/compensating-controls/new">New control</Link>}
      </div>
      <p className="muted">Structured, AO-signed compensating controls (NIST 800-53A §2.4 / CA-5(1) / PL-2). An active, unexpired control referenced by an approved acceptance fills the POA&amp;M risk's <code>remediations[]</code> with <code>lifecycle=completed</code>.</p>

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
              <th>Title</th><th>Status</th><th>NIST controls</th><th>Sign-off</th><th>Expiration</th><th></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={6} className="muted">No compensating controls.</td></tr>}
            {rows.map((r) => (
              <tr key={r.uuid}>
                <td>{r.title}</td>
                <td>{r.status}</td>
                <td>{r.nist_control_ids.map((c) => <code key={c} style={{ marginRight: 4 }}>{c}</code>)}</td>
                <td>{r.signed_off_at ? r.signed_off_at.slice(0, 10) : <span className="muted">unsigned</span>}</td>
                <td>{r.expiration_date ? r.expiration_date.slice(0, 10) : <span className="muted">none</span>}</td>
                <td><Link to={`/compensating-controls/${r.uuid}`}>Details</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
