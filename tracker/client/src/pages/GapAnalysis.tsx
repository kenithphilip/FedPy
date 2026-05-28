import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { ApplicabilityPill, KeywordPill, StatusPill } from '../lib/formatting';

export function GapAnalysis() {
  const { data: reqs } = useQuery({
    queryKey: ['gap-reqs'],
    queryFn: () => api.requirements({ status: 'not_started' }),
  });
  const { data: blocked } = useQuery({
    queryKey: ['gap-reqs-blocked'],
    queryFn: () => api.requirements({ status: 'blocked' }),
  });
  const { data: inds } = useQuery({
    queryKey: ['gap-inds'],
    queryFn: () => api.indicators({ status: 'not_started' }),
  });

  // Group indicators by domain
  const indByDomain: Record<string, any[]> = {};
  for (const i of inds?.indicators ?? []) {
    (indByDomain[i.domain_id] ??= []).push(i);
  }

  // Group requirements by process
  const reqByProcess: Record<string, any[]> = {};
  for (const r of reqs?.requirements ?? []) {
    (reqByProcess[r.process_id] ??= []).push(r);
  }

  return (
    <div>
      <h1 className="h1">Gap analysis</h1>
      <p className="muted small">
        Everything you haven't started yet, grouped for triage. Start with MUST requirements
        and Key Security Indicators — those are the load-bearing pieces for 20x.
      </p>

      <h2 className="h2">KSIs — not started ({inds?.indicators.length ?? 0})</h2>
      {Object.keys(indByDomain).length === 0 && (
        <div className="card muted">No outstanding KSIs.</div>
      )}
      {Object.entries(indByDomain).map(([dom, items]) => (
        <div className="card" key={dom} style={{ padding: 0 }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
            <strong>{dom}</strong> <span className="muted small">· {items.length} indicator(s)</span>
          </div>
          <table className="table">
            <thead>
              <tr><th>ID</th><th>Name</th><th>Statement</th><th>NIST controls</th></tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id}>
                  <td><Link to={`/indicators/${i.id}`} className="mono">{i.id}</Link></td>
                  <td>{i.name}</td>
                  <td>{i.statement}</td>
                  <td className="small mono muted">{(i.controls ?? []).join(', ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      <h2 className="h2">Requirements — not started ({reqs?.requirements.length ?? 0})</h2>
      {Object.keys(reqByProcess).length === 0 && (
        <div className="card muted">No outstanding requirements.</div>
      )}
      {Object.entries(reqByProcess).map(([proc, items]) => (
        <div className="card" key={proc} style={{ padding: 0 }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
            <strong>{proc}</strong> <span className="muted small">· {items.length} requirement(s)</span>
          </div>
          <table className="table">
            <thead>
              <tr><th>ID</th><th>KW</th><th>App.</th><th>Actor</th><th>Statement</th></tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td><Link to={`/requirements/${r.id}`} className="mono">{r.id}</Link></td>
                  <td><KeywordPill kw={r.primary_key_word} /></td>
                  <td><ApplicabilityPill applicability={r.applicability} /></td>
                  <td>{r.actor_label}</td>
                  <td>{r.name ? <strong>{r.name}: </strong> : null}{r.statement}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {(blocked?.requirements?.length ?? 0) > 0 && (
        <>
          <h2 className="h2">Blocked ({blocked!.requirements.length})</h2>
          <div className="card" style={{ padding: 0 }}>
            <table className="table">
              <thead>
                <tr><th>ID</th><th>Process</th><th>Statement</th><th>Status</th></tr>
              </thead>
              <tbody>
                {blocked!.requirements.map((r) => (
                  <tr key={r.id}>
                    <td><Link to={`/requirements/${r.id}`} className="mono">{r.id}</Link></td>
                    <td>{r.process_id}</td>
                    <td>{r.statement}</td>
                    <td><StatusPill status={r.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
