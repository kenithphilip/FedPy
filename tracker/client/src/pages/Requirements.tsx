import { useQuery } from '@tanstack/react-query';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api';
import { ApplicabilityPill, KeywordPill, StatusPill, STATUSES, STATUS_LABEL } from '../lib/formatting';

export function Requirements() {
  const [sp, setSp] = useSearchParams();
  const filters = {
    process: sp.get('process') ?? '',
    applicability: sp.get('applicability') ?? '',
    actor: sp.get('actor') ?? '',
    status: sp.get('status') ?? '',
    q: sp.get('q') ?? '',
  };

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(sp);
    if (v) next.set(k, v); else next.delete(k);
    setSp(next, { replace: true });
  };

  const { data: procs } = useQuery({ queryKey: ['processes'], queryFn: () => api.processes() });
  const { data, isLoading } = useQuery({
    queryKey: ['requirements', filters],
    queryFn: () => api.requirements(filters as any),
  });

  return (
    <div>
      <h1 className="h1">Requirements</h1>

      <div className="filters">
        <div>
          <label>Process</label>
          <select value={filters.process} onChange={(e) => set('process', e.target.value)}>
            <option value="">All</option>
            {procs?.processes.map((p: any) => <option key={p.id} value={p.id}>{p.id} — {p.name}</option>)}
          </select>
        </div>
        <div>
          <label>Applicability</label>
          <select value={filters.applicability} onChange={(e) => set('applicability', e.target.value)}>
            <option value="">All</option>
            <option value="20x">20x</option>
            <option value="rev5">Rev5</option>
            <option value="both">Both</option>
          </select>
        </div>
        <div>
          <label>Status</label>
          <select value={filters.status} onChange={(e) => set('status', e.target.value)}>
            <option value="">All</option>
            {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </div>
        <div>
          <label>Actor</label>
          <input value={filters.actor} onChange={(e) => set('actor', e.target.value)} placeholder="e.g. CSO" />
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
              <th>Process</th>
              <th>Actor</th>
              <th>App.</th>
              <th>KW</th>
              <th>Statement</th>
              <th>Status</th>
              <th>Owner</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={8} className="muted" style={{ padding: 18 }}>Loading…</td></tr>
            ) : !data?.requirements.length ? (
              <tr><td colSpan={8} className="muted" style={{ padding: 18 }}>No requirements match.</td></tr>
            ) : data.requirements.map((r: any) => (
              <tr key={r.id}>
                <td><Link to={`/requirements/${r.id}`} className="mono">{r.id}</Link></td>
                <td>{r.process_id}</td>
                <td>{r.actor_label}</td>
                <td><ApplicabilityPill applicability={r.applicability} /></td>
                <td><KeywordPill kw={r.primary_key_word} /></td>
                <td>{r.name ? <strong>{r.name}: </strong> : null}{r.statement}</td>
                <td><StatusPill status={r.status} /></td>
                <td className="small muted">{r.owner_name ?? r.owner_text ?? ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">{data?.requirements.length ?? 0} item(s)</p>
    </div>
  );
}
