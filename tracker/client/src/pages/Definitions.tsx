import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../lib/api';

export function Definitions() {
  const { data, isLoading } = useQuery({ queryKey: ['definitions'], queryFn: () => api.definitions() });
  const [q, setQ] = useState('');

  const filtered = (data?.definitions ?? []).filter((d: any) => {
    if (!q) return true;
    const needle = q.toLowerCase();
    return d.term.toLowerCase().includes(needle)
      || d.definition.toLowerCase().includes(needle)
      || d.id.toLowerCase().includes(needle);
  });

  return (
    <div>
      <h1 className="h1">FedRAMP definitions (FRD)</h1>
      <div className="filters">
        <div style={{ flex: 1, minWidth: 280 }}>
          <label>Search</label>
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="term or text…" />
        </div>
      </div>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 110 }}>ID</th>
              <th style={{ width: 200 }}>Term</th>
              <th>Definition</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? <tr><td colSpan={3} className="muted" style={{ padding: 18 }}>Loading…</td></tr> :
             filtered.map((d: any) => (
              <tr key={d.id}>
                <td className="mono">{d.id}</td>
                <td><strong>{d.term}</strong></td>
                <td>{d.definition}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">{filtered.length} term(s)</p>
    </div>
  );
}
