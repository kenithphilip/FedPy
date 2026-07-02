import React, { useState } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';
import { AuthProvider, useAuth } from './lib/auth';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';
import { Requirements } from './pages/Requirements';
import { Indicators } from './pages/Indicators';
import { ItemDetail } from './pages/ItemDetail';
import { Crosswalk } from './pages/Crosswalk';
import { GapAnalysis } from './pages/GapAnalysis';
import { Definitions } from './pages/Definitions';
import { Export } from './pages/Export';
import { CollectorRuns } from './pages/CollectorRuns';
import { ApiTokens } from './pages/ApiTokens';
import { TwoFactor } from './pages/TwoFactor';
import { RbacAdmin } from './pages/RbacAdmin';
import { AuditSearch } from './pages/AuditSearch';
import { RiskAcceptance } from './pages/RiskAcceptance';
import { RiskAcceptanceCreate } from './pages/RiskAcceptanceCreate';
import { RiskAcceptanceDetail } from './pages/RiskAcceptanceDetail';
import { canViewRiskAcceptances } from './lib/risk-acceptance-view';

export function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  );
}

function Gate() {
  const { user, loading, awaiting2fa } = useAuth();
  if (loading) return <div className="center-box muted">Loading…</div>;
  if (!user) return <Login />;
  if (awaiting2fa) return <TwoFactorChallenge />;
  return <Shell />;
}

/**
 * Mid-login interstitial: server returned `requires_2fa: true` from /api/auth/login.
 * The user holds a pre-auth session cookie; the server will reject all other
 * routes until this verify call succeeds. Falling out of this screen requires
 * either entering a valid code or logging out.
 */
function TwoFactorChallenge() {
  const { verify2fa, logout } = useAuth();
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      await verify2fa(code.trim());
    } catch (e: any) {
      setError(e?.message ?? 'Invalid code');
    } finally { setBusy(false); }
  }

  return (
    <div className="center-box">
      <h1>Two-factor verification</h1>
      <p className="muted">Enter the 6-digit code from your authenticator app, or a backup code.</p>
      {error && <div className="alert error">{error}</div>}
      <form onSubmit={submit}>
        <input
          autoFocus
          type="text"
          inputMode="numeric"
          placeholder="123456"
          value={code}
          onChange={(e) => setCode(e.target.value)}
          style={{ fontSize: 24, letterSpacing: 4, width: 200 }}
        />
        <div style={{ marginTop: 12 }}>
          <button className="primary" type="submit" disabled={busy || code.length < 6}>Verify</button>
          <button className="ghost" type="button" onClick={() => logout()}>Cancel</button>
        </div>
      </form>
    </div>
  );
}

function Shell() {
  const { user, logout } = useAuth();
  return (
    <div className="app">
      <div className="header">
        <div className="brand">FedRAMP 20x Tracker</div>
        <div className="user">
          <span>{user!.name} · <span className="muted">{user!.role}</span></span>
          <button className="ghost" onClick={() => logout()}>Sign out</button>
        </div>
      </div>
      <nav className="sidebar">
        <div className="group">Overview</div>
        <NavLink to="/" end>Dashboard</NavLink>
        <NavLink to="/gap-analysis">Gap analysis</NavLink>
        <div className="group">Catalog</div>
        <NavLink to="/requirements">Requirements</NavLink>
        <NavLink to="/indicators">KSIs</NavLink>
        <NavLink to="/crosswalk">NIST crosswalk</NavLink>
        <NavLink to="/definitions">Definitions</NavLink>
        {canViewRiskAcceptances(user!.role) && (
          <>
            <div className="group">Risk</div>
            <NavLink to="/risk-acceptance">Risk acceptances</NavLink>
          </>
        )}
        <div className="group">Reports</div>
        <NavLink to="/export">Export</NavLink>
        <NavLink to="/collector-runs">Collector runs</NavLink>
        <div className="group">Account</div>
        <NavLink to="/two-factor">Two-factor auth</NavLink>
        {user!.role === 'admin' && (
          <>
            <div className="group">Admin</div>
            <NavLink to="/api-tokens">API tokens</NavLink>
            <NavLink to="/users">Users & roles</NavLink>
          </>
        )}
        {['admin', 'auditor'].includes(user!.role) && (
          <NavLink to="/audit-log">Audit log</NavLink>
        )}
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/gap-analysis" element={<GapAnalysis />} />
          <Route path="/requirements" element={<Requirements />} />
          <Route path="/requirements/:id" element={<ItemDetail kind="requirement" />} />
          <Route path="/indicators" element={<Indicators />} />
          <Route path="/indicators/:id" element={<ItemDetail kind="indicator" />} />
          <Route path="/crosswalk" element={<Crosswalk />} />
          <Route path="/definitions" element={<Definitions />} />
          <Route path="/export" element={<Export />} />
          <Route path="/collector-runs" element={<CollectorRuns />} />
          <Route path="/api-tokens" element={<ApiTokens />} />
          <Route path="/two-factor" element={<TwoFactor />} />
          <Route path="/users" element={<RbacAdmin />} />
          <Route path="/audit-log" element={<AuditSearch />} />
          <Route path="/risk-acceptance" element={<RiskAcceptance />} />
          <Route path="/risk-acceptance/new" element={<RiskAcceptanceCreate />} />
          <Route path="/risk-acceptance/:id" element={<RiskAcceptanceDetail />} />
        </Routes>
      </main>
    </div>
  );
}
