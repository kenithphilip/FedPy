import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

export function ApiTokens() {
  const { user } = useAuth();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['tokens'], queryFn: () => api.tokensList() });
  const [newName, setNewName] = useState('');
  const [newScope, setNewScope] = useState('patch:indicators');
  const [createdToken, setCreatedToken] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.tokenCreate(newName, newScope),
    onSuccess: (data) => {
      setCreatedToken(data.token);
      setNewName('');
      qc.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: number) => api.tokenRevoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }),
  });

  if (user?.role !== 'admin') {
    return <div className="card muted">Admin role required.</div>;
  }

  return (
    <div>
      <h1 className="h1">API tokens</h1>
      <p className="muted small">For headless integrations (cloud-evidence collector push, CI workflows). Tokens are shown ONCE at creation.</p>

      {createdToken && (
        <div className="card" style={{ background: 'rgba(63,185,80,0.08)', borderColor: 'var(--ok)' }}>
          <strong>New token created. Copy now — it will not be shown again.</strong>
          <pre className="mono" style={{ marginTop: 8, padding: 8, background: 'var(--panel-2)', borderRadius: 6, overflow: 'auto', userSelect: 'all' }}>{createdToken}</pre>
          <button className="secondary" onClick={() => setCreatedToken(null)}>Dismiss</button>
        </div>
      )}

      <div className="card">
        <strong>Create new token</strong>
        <div className="row" style={{ marginTop: 10, gap: 10 }}>
          <div style={{ flex: 1 }}>
            <label>Name</label>
            <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g. cloud-evidence collector" />
          </div>
          <div style={{ width: 200 }}>
            <label>Scope</label>
            <select value={newScope} onChange={(e) => setNewScope(e.target.value)}>
              <option value="patch:indicators">patch:indicators</option>
              <option value="patch:all">patch:all</option>
              <option value="read:all">read:all</option>
            </select>
          </div>
          <div>
            <label>&nbsp;</label>
            <button onClick={() => create.mutate()} disabled={create.isPending || newName.length < 3}>
              {create.isPending ? '…' : 'Create'}
            </button>
          </div>
        </div>
        {create.isError && <p className="small" style={{ color: 'var(--err)' }}>{(create.error as Error).message}</p>}
      </div>

      <h2 className="h2">Existing tokens</h2>
      <div className="card" style={{ padding: 0 }}>
        <table className="table">
          <thead>
            <tr><th>Name</th><th>Scope</th><th>Created</th><th>Last used</th><th>Expires</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {isLoading ? <tr><td colSpan={7} className="muted" style={{ padding: 18 }}>Loading…</td></tr> :
             (data?.tokens ?? []).map((t: any) => (
              <tr key={t.id}>
                <td>{t.name}</td>
                <td className="mono small">{t.scope}</td>
                <td className="small">{t.created_at}</td>
                <td className="small">{t.last_used ?? '—'}</td>
                <td className="small">{t.expires_at ?? '—'}</td>
                <td>{t.revoked_at ? <span style={{ color: 'var(--err)' }}>revoked</span> : <span style={{ color: 'var(--ok)' }}>active</span>}</td>
                <td>
                  {!t.revoked_at && <button className="danger" onClick={() => revoke.mutate(t.id)} disabled={revoke.isPending}>Revoke</button>}
                </td>
              </tr>
            ))}
            {!isLoading && (data?.tokens?.length ?? 0) === 0 && (
              <tr><td colSpan={7} className="muted" style={{ padding: 18 }}>No tokens yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
