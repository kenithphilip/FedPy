import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { StatusPill, STATUSES, STATUS_LABEL } from '../lib/formatting';

export function Indicators() {
  const [sp, setSp] = useSearchParams();
  const filters = {
    domain: sp.get('domain') ?? '',
    status: sp.get('status') ?? '',
    q: sp.get('q') ?? '',
  };
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v); else next.delete(k);
    setSp(next, { replace: true });
  };

  const { data: domains } = useQuery({ queryKey: ['ksi-domains'], queryFn: () => api.ksiDomains() });
  const { data, isLoading } = useQuery({
    queryKey: ['indicators', filters],
    queryFn: () => api.indicators(filters as any),
  });

  return (
    <div>
      <h1 className="h1">Key Security Indicators</h1>

      <div className="filters">
        <div>
          <label>Domain</label>
          <select value={filters.domain} onChange={(e) => set('domain', e.target.value)}>
            <option value="">All</option>
            {domains?.domains.map((d: any) => <option key={d.id} value={d.id}>{d.id} — {d.name}</option>)}
          </select>
        </div>
        <div>
          <label>Status</label>
          <select value={filters.status} onChange={(e) => set('status', e.target.value)}>
            <option value="">All</option>
            {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <label>Search</label>
          <input value={filters.q} onChange={(e) => set('q', e.target.value)} placeholder="text search…" />
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Domain</th>
              <th>Name</th>
              <th>Statement</th>
              <th>NIST controls</th>
              <th>Status</th>
              <th>Owner</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={7} className="muted" style={{ padding: 18 }}>Loading…</td></tr>
            ) : !data?.indicators.length ? (
              <tr><td colSpan={7} className="muted" style={{ padding: 18 }}>No indicators match.</td></tr>
            ) : data.indicators.map((i: any) => (
              <tr key={i.id}>
                <td><Link to={`/indicators/${i.id}`} className="mono">{i.id}</Link></td>
                <td>{i.domain_id}</td>
                <td>{i.name}</td>
                <td>{i.statement}</td>
                <td className="small mono muted">{(i.controls ?? []).join(', ')}</td>
                <td><StatusPill status={i.status} /></td>
                <td className="small muted">{i.owner_name ?? i.owner_text ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">{data?.indicators.length ?? 0} item(s)</p>
    </div>
  );
}
