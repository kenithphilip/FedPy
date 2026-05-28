import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';

export function CollectorRuns() {
  const { data: latest } = useQuery({ queryKey: ['collector-latest'], queryFn: () => api.collectorLatest() });
  const { data: list } = useQuery({ queryKey: ['collector-list'], queryFn: () => api.collectorList() });

  const run = latest?.run;
  const summary = parseSummary(run?.summary_json);
  const impact = summary?.impact_level as string | undefined;
  const awareness = summary?.rollup?.awareness_tracked as number | undefined;

  return (
    <div>
      <h1 className="h1">Collector runs</h1>
      <p className="muted small">Telemetry pushed by the cloud-evidence collector after each run.</p>

      {run ? (
        <div className="card">
          <div className="row">
            <strong>Latest run</strong>
            {impact ? <ImpactBadge level={impact} /> : null}
            <span className="spacer" />
            <span className="muted small mono">{run.run_id}</span>
          </div>
          <div className="grid cols-4" style={{ marginTop: 12 }}>
            <Stat label="Total requirements" value={run.total_ksis} />
            <Stat label="Passing" value={run.passed_ksis} color="var(--ok)" />
            <Stat label="Failing" value={run.failed_ksis} color={run.failed_ksis > 0 ? 'var(--err)' : undefined} />
            {typeof awareness === 'number'
              ? <Stat label="Awareness (tracked)" value={awareness} />
              : <Stat label="Negative drift" value={run.negative_drift} color={run.negative_drift > 0 ? 'var(--err)' : undefined} />}
          </div>
          <p className="muted small" style={{ marginTop: 12 }}>
            Started {run.started_at} · Finished {run.finished_at ?? 'in progress'} · FRMR {run.frmr_version}
            {impact === 'high' ? <> · <span title="High applicability is derived from the NIST 800-53 Rev5 baseline (no published 20x High).">High = Rev5-derived</span></> : null}
            {run.token_name ? <> · pushed via API token <span className="mono">{run.token_name}</span></> : null}
            {run.pushed_by_name ? <> · pushed by {run.pushed_by_name}</> : null}
          </p>
        </div>
      ) : (
        <div className="card muted">No collector runs yet. Run <span className="mono">npx tsx core/orchestrator.ts --push-tracker</span> from cloud-evidence.</div>
      )}

      <h2 className="h2">Recent runs</h2>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Started</th>
              <th>FRMR</th>
              <th>KSIs</th>
              <th>Pass</th>
              <th>Fail</th>
              <th>Drift</th>
              <th>Neg.</th>
              <th>Pushed by</th>
            </tr>
          </thead>
          <tbody>
            {(list?.runs ?? []).map((r: any) => (
              <tr key={r.id}>
                <td className="mono small">{r.run_id.slice(0, 8)}…</td>
                <td className="small">{r.started_at}</td>
                <td className="small mono">{r.frmr_version}</td>
                <td>{r.total_ksis}</td>
                <td style={{ color: 'var(--ok)' }}>{r.passed_ksis}</td>
                <td style={{ color: r.failed_ksis > 0 ? 'var(--err)' : undefined }}>{r.failed_ksis}</td>
                <td>{r.drift_events}</td>
                <td style={{ color: r.negative_drift > 0 ? 'var(--err)' : undefined }}>{r.negative_drift}</td>
                <td className="small muted">{r.token_name ?? r.pushed_by_name ?? '—'}</td>
              </tr>
            ))}
            {(!list?.runs || list.runs.length === 0) && (
              <tr><td colSpan={9} className="muted" style={{ padding: 18 }}>No runs to display.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div>
      <div style={{ fontSize: 24, fontWeight: 600, color }}>{value}</div>
      <div className="small muted" style={{ textTransform: 'uppercase', letterSpacing: 0.3 }}>{label}</div>
    </div>
  );
}

/** Impact-tier chip on the latest collector run. */
function ImpactBadge({ level }: { level: string }) {
  const color = level === 'high' ? 'var(--err)' : level === 'moderate' ? 'var(--warn, #b8860b)' : 'var(--ok)';
  return (
    <span style={{ marginLeft: 8, border: `1px solid ${color}`, color, borderRadius: 6, padding: '2px 8px', fontSize: 12, fontWeight: 600 }}>
      Impact: {level.charAt(0).toUpperCase() + level.slice(1)}
    </span>
  );
}

/** summary_json may arrive as an object or a JSON string; parse defensively. */
function parseSummary(raw: unknown): any | undefined {
  if (!raw) return undefined;
  if (typeof raw === 'object') return raw;
  if (typeof raw === 'string') { try { return JSON.parse(raw); } catch { return undefined; } }
  return undefined;
}
