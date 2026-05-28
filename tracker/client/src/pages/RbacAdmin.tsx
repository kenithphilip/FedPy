import { useEffect, useState } from 'react';
import { api } from '../lib/api';

/**
 * Admin RBAC page.
 *
 * Lists every user with their role + 2FA status. Admins can:
 *   - Change a user's role (viewer / contributor / ksi-owner / auditor / admin)
 *   - Assign / unassign per-KSI-domain ownership (e.g. "Bob owns IAM")
 *
 * All changes are recorded in audit_log via the server.
 *
 * Permission: requires `admin` role (the server enforces; we hide the link
 * from the sidebar in App.tsx for non-admins).
 */
const ROLES = ['viewer', 'contributor', 'ksi-owner', 'auditor', 'admin'];

// Curated list of KSI domains used in our FRMR catalog. The server doesn't
// constrain values, but the UI dropdown should show the canonical set.
const KSI_DOMAINS = ['IAM', 'CNA', 'MLA', 'CMT', 'SVC', 'RPL', 'PIY', 'SCR', 'INR', 'AFR', 'CED', 'CSX'];

interface UserRow {
  id: number;
  email: string;
  name: string;
  role: string;
  created_at: string;
  twofa_enrolled: number;
  require_2fa: number;
}

export function RbacAdmin() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [domains, setDomains] = useState<Record<number, string[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assignDomainInput, setAssignDomainInput] = useState<Record<number, string>>({});

  const reload = async () => {
    setError(null); setLoading(true);
    try {
      const r = await api.usersList();
      setUsers(r.users as any);
      const doms: Record<number, string[]> = {};
      for (const u of r.users) {
        const d = await api.userDomains(u.id);
        doms[u.id] = d.domains;
      }
      setDomains(doms);
    } catch (e: any) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { reload(); }, []);

  async function changeRole(userId: number, newRole: string) {
    try {
      await api.userSetRole(userId, newRole);
      await reload();
    } catch (e: any) { setError(`Role change failed: ${e.message}`); }
  }

  async function assignDomain(userId: number) {
    const domain = (assignDomainInput[userId] ?? '').trim().toUpperCase();
    if (!domain) return;
    try {
      await api.userAssignDomain(userId, domain);
      setAssignDomainInput((m) => ({ ...m, [userId]: '' }));
      await reload();
    } catch (e: any) { setError(`Assign failed: ${e.message}`); }
  }

  async function unassignDomain(userId: number, domain: string) {
    try {
      await api.userUnassignDomain(userId, domain);
      await reload();
    } catch (e: any) { setError(`Unassign failed: ${e.message}`); }
  }

  if (loading) return <div className="muted">Loading…</div>;

  return (
    <div className="page">
      <h1>Users &amp; roles</h1>
      <p className="muted">
        Manage tracker roles and per-KSI-domain ownership. Every change is recorded in the audit log.
      </p>
      {error && <div className="alert error">{error}</div>}

      <table className="table" style={{ width: '100%' }}>
        <thead>
          <tr>
            <th>User</th>
            <th>Role</th>
            <th>2FA</th>
            <th>KSI domains</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>
                <div><strong>{u.name}</strong></div>
                <div className="muted">{u.email}</div>
              </td>
              <td>
                <select value={u.role} onChange={(e) => changeRole(u.id, e.target.value)}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  {!ROLES.includes(u.role) && <option value={u.role}>{u.role} (legacy)</option>}
                </select>
              </td>
              <td>
                {u.twofa_enrolled ? '✓ enrolled' : <span className="muted">not enrolled</span>}
                {u.require_2fa ? ' · required' : ''}
              </td>
              <td>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {(domains[u.id] ?? []).map((d) => (
                    <span key={d} className="chip">
                      {d}
                      <button className="chip-x" onClick={() => unassignDomain(u.id, d)} title="Unassign">×</button>
                    </span>
                  ))}
                </div>
                <div style={{ marginTop: 8 }}>
                  <input
                    list={`dom-list-${u.id}`}
                    placeholder="Add domain"
                    value={assignDomainInput[u.id] ?? ''}
                    onChange={(e) => setAssignDomainInput((m) => ({ ...m, [u.id]: e.target.value }))}
                    onKeyDown={(e) => { if (e.key === 'Enter') assignDomain(u.id); }}
                    style={{ width: 120 }}
                  />
                  <datalist id={`dom-list-${u.id}`}>
                    {KSI_DOMAINS.map((d) => <option key={d} value={d} />)}
                  </datalist>
                  <button className="ghost" onClick={() => assignDomain(u.id)}>Add</button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
