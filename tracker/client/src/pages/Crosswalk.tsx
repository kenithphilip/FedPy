import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { StatusPill, percent } from '../lib/formatting';

export function Crosswalk() {
  const { data, isLoading } = useQuery({ queryKey: ['crosswalk'], queryFn: () => api.crosswalk() });
  const [family, setFamily] = useState('');
  const [q, setQ] = useState('');

  const families = useMemo(() => {
    const set = new Set<string>();
    for (const c of data?.controls ?? []) set.add(c.family);
    return Array.from(set).sort();
  }, [data]);

  const filtered = useMemo(() => {
    const ctrls = data?.controls ?? [];
    return ctrls.filter((c) => {
      if (family && c.family !== family) return false;
      if (q && !c.control_id.toLowerCase().includes(q.toLowerCase())) return false;
      return true;
    });
  }, [data, family, q]);

  if (isLoading) return <div className="muted">Loading…</div>;

  return (
    <div>
      <h1 className="h1">NIST 800-53 crosswalk</h1>
      <p className="muted small">
        For each NIST control referenced by a Key Security Indicator, the indicators that satisfy it
        and their current tracker status. Use this when mapping FedRAMP 20x against an existing
        Rev5 / NIST-based control baseline.
      </p>

      <div className="filters">
        <div>
          <label>Control family</label>
          <select value={family} onChange={(e) => setFamily(e.target.value)}>
            <option value="">All</option>
            {families.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
          </select>
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <label>Search control</label>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="e.g. ac-2, ia-5" />
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 110 }}>Control</th>
              <th>Indicators</th>
              <th style={{ width: 110 }}>Done</th>
              <th>Counts</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => (
              <tr key={c.control_id}>
                <td className="mono"><strong>{c.control_id}</strong></td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.indicators.map((ind: any) => (
                      <Link key={ind.id} to={`/indicators/${ind.id}`} className="small"
                            style={{ display: 'inline-flex', gap: 6, alignItems: 'center',
                                     background: 'var(--panel-2)', padding: '2px 8px', borderRadius: 999,
                                     border: '1px solid var(--border)' }}>
                        <span className="mono">{ind.id}</span>
                        <StatusPill status={ind.status} />
                      </Link>
                    ))}
                  </div>
                </td>
                <td>{percent(c.status_counts)}%</td>
                <td className="small muted">
                  {c.status_counts.met ?? 0} met · {c.status_counts.in_progress ?? 0} in-prog · {c.status_counts.not_started ?? 0} todo
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">{filtered.length} control(s)</p>
    </div>
  );
}
