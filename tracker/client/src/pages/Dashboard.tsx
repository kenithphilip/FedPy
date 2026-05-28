import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../lib/api';
import { ApplicabilityPill, KeywordPill, ProgressBar, percent } from '../lib/formatting';

export function Dashboard() {
  const { data, isLoading } = useQuery({ queryKey: ['dashboard'], queryFn: () => api.dashboard() });
  const { data: meta } = useQuery({ queryKey: ['meta'], queryFn: () => api.meta() });

  if (isLoading || !data) return <div className="muted">Loading…</div>;

  return (
    <div>
      <h1 className="h1">Dashboard</h1>
      {meta?.meta && (
        <p className="muted small">
          FRMR v{meta.meta.version} · updated {meta.meta.last_updated} · ingested {meta.meta.ingested_at?.slice(0,10)}
        </p>
      )}

      <div className="grid cols-2">
        <div className="card">
          <div className="row">
            <strong>FRR Requirements</strong>
            <span className="spacer" />
            <span className="muted small">{percent(data.overall.requirements)}% done</span>
          </div>
          <div style={{ margin: '10px 0' }}>
            <ProgressBar counts={data.overall.requirements} />
          </div>
          <CountLine c={data.overall.requirements} />
        </div>

        <div className="card">
          <div className="row">
            <strong>Key Security Indicators</strong>
            <span className="spacer" />
            <span className="muted small">{percent(data.overall.indicators)}% done</span>
          </div>
          <div style={{ margin: '10px 0' }}>
            <ProgressBar counts={data.overall.indicators} />
          </div>
          <CountLine c={data.overall.indicators} />
        </div>
      </div>

      <h2 className="h2">By process</h2>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Process</th>
              <th>Done</th>
              <th style={{ width: 220 }}>Progress</th>
              <th>Counts</th>
            </tr>
          </thead>
          <tbody>
            {data.by_process.map((p) => (
              <tr key={p.id}>
                <td><Link to={`/requirements?process=${p.id}`}><strong>{p.id}</strong></Link> <span className="muted small">{p.name}</span></td>
                <td>{percent(p.counts)}%</td>
                <td><ProgressBar counts={p.counts} /></td>
                <td className="small muted"><CountLine c={p.counts} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="h2">By KSI domain</h2>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Done</th>
              <th style={{ width: 220 }}>Progress</th>
              <th>Counts</th>
            </tr>
          </thead>
          <tbody>
            {data.by_domain.map((d) => (
              <tr key={d.id}>
                <td><Link to={`/indicators?domain=${d.id}`}><strong>{d.id}</strong></Link> <span className="muted small">{d.name}</span></td>
                <td>{percent(d.counts)}%</td>
                <td><ProgressBar counts={d.counts} /></td>
                <td className="small muted"><CountLine c={d.counts} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="h2">Next 10 to tackle</h2>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Process</th>
              <th>KW</th>
              <th>App.</th>
              <th>Statement</th>
            </tr>
          </thead>
          <tbody>
            {data.next_up.map((r: any) => (
              <tr key={r.id}>
                <td><Link to={`/requirements/${r.id}`} className="mono">{r.id}</Link></td>
                <td>{r.process_id}</td>
                <td><KeywordPill kw={r.primary_key_word} /></td>
                <td><ApplicabilityPill applicability={r.applicability} /></td>
                <td>{r.statement}</td>
              </tr>
            ))}
            {!data.next_up.length && (
              <tr><td colSpan={5} className="muted" style={{ padding: 18 }}>Everything is past the not-started bucket.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CountLine({ c }: { c: Record<string, number> }) {
  return (
    <div className="row small" style={{ flexWrap: 'wrap', gap: 12 }}>
      <span><strong>{c.total ?? 0}</strong> total</span>
      <span style={{ color: 'var(--ok)' }}>{c.met ?? 0} met</span>
      <span style={{ color: 'var(--accent)' }}>{c.in_progress ?? 0} in progress</span>
      <span style={{ color: 'var(--blocked)' }}>{c.blocked ?? 0} blocked</span>
      <span className="muted">{c.not_applicable ?? 0} N/A</span>
      <span className="muted">{c.not_started ?? 0} not started</span>
    </div>
  );
}
