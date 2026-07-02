import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { riskRegisterApi, type RegisterEntry } from '../lib/risk-register-api';
import { canCreateOrganisationalRisk, sortByInherentDescending } from '../lib/risk-register-view';

/**
 * LOOP-B.B5 — Central Risk Register list view. Shows the tracker-resident
 * aggregated register (organisational risks + approved acceptances), sorted by
 * inherent risk (very-high first). "Add organisational risk" CTA is shown only to
 * iso/ao/admin; "Export to XLSX" streams the server-rendered workbook. The
 * finding-sourced RA-3 entries live in the collector's signed out/risk-register.json.
 */
export function RiskRegister() {
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [entries, setEntries] = useState<RegisterEntry[]>([]);
  const [summary, setSummary] = useState<{ entries_total: number; high_inherent_count: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    setError(null); setLoading(true);
    try {
      const r = await riskRegisterApi.register();
      setEntries(sortByInherentDescending(r.entries));
      setSummary({ entries_total: r.summary.entries_total, high_inherent_count: r.summary.high_inherent_count });
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, []);

  const bandStyle = (b: string): React.CSSProperties =>
    b === 'very-high' ? { color: '#9C0006', fontWeight: 600 } : b === 'high' ? { color: '#9C0006' } : {};

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1>Risk register</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <a className="ghost" href={riskRegisterApi.exportXlsxUrl()} download>Export to XLSX</a>
          {canCreateOrganisationalRisk(role) && <Link className="primary" to="/risk-register/organisational/new">Add organisational risk</Link>}
        </div>
      </div>
      <p className="muted">
        Aggregated risk register (NIST SP 800-53 Rev 5 RA-3). Likelihood/impact use the NIST SP 800-30 Rev 1
        qualitative scale. Finding-sourced entries are aggregated by the collector into the signed
        <code> out/risk-register.json</code>; this view shows the tracker-resident organisational risks + approved acceptances.
      </p>
      {summary && <p className="muted">{summary.entries_total} entr{summary.entries_total === 1 ? 'y' : 'ies'} · {summary.high_inherent_count} high/very-high inherent</p>}

      {error && <div className="alert error">{error}</div>}
      {loading ? <div className="muted">Loading…</div> : (
        <table>
          <thead>
            <tr>
              <th>Title</th><th>Source</th><th>Category</th><th>Likelihood</th><th>Impact</th>
              <th>Inherent</th><th>Residual</th><th>Treatment</th><th>Owner</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && <tr><td colSpan={11} className="muted">No risks in the register.</td></tr>}
            {entries.map((e) => (
              <tr key={`${e.source}:${e.uuid}`}>
                <td>{e.title}</td>
                <td>{e.source}</td>
                <td>{e.category}</td>
                <td>{e.likelihood}</td>
                <td>{e.impact}</td>
                <td style={bandStyle(e.inherent_risk)}>{e.inherent_risk}</td>
                <td style={bandStyle(e.residual_risk)}>{e.residual_risk}</td>
                <td>{e.treatment}</td>
                <td>{e.owner}</td>
                <td>{e.status}</td>
                <td>{e.source === 'organisational' ? <Link to={`/risk-register/organisational/${e.uuid}`}>Details</Link> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
