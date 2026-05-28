import { useState } from 'react';
import { useAuth } from '../lib/auth';

export function Login() {
  const { login, needsBootstrap, signup } = useAuth();
  const [mode, setMode] = useState<'login' | 'signup'>(needsBootstrap ? 'signup' : 'login');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    setBusy(true);
    try {
      if (mode === 'login') await login(email, password);
      else await signup(email, name, password);
    } catch (e: any) {
      setErr(e.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const title = needsBootstrap ? 'Create the first admin' : mode === 'login' ? 'Sign in' : 'Sign up';
  const sub = needsBootstrap
    ? 'No users exist yet. The first account becomes the admin.'
    : 'FedRAMP 20x Tracker';

  return (
    <div className="center-box">
      <form className="auth-card" onSubmit={submit}>
        <h1>{title}</h1>
        <p className="sub">{sub}</p>

        {mode === 'signup' && (
          <>
            <label>Name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
          </>
        )}

        <label>Email</label>
        <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required
               autoFocus={mode === 'login'} />

        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
               required minLength={mode === 'signup' ? 8 : undefined} />

        {err && <div className="err">{err}</div>}

        <button type="submit" disabled={busy}>
          {busy ? '…' : mode === 'login' ? 'Sign in' : (needsBootstrap ? 'Create admin' : 'Create user')}
        </button>

        {!needsBootstrap && (
          <div className="alt">
            {mode === 'login' ? (
              <a href="#" onClick={(e) => { e.preventDefault(); setMode('signup'); setErr(''); }}>
                Create account (admin invite only)
              </a>
            ) : (
              <a href="#" onClick={(e) => { e.preventDefault(); setMode('login'); setErr(''); }}>
                Back to sign in
              </a>
            )}
          </div>
        )}
      </form>
    </div>
  );
}
