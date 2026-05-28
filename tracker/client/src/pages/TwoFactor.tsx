import { useEffect, useState } from 'react';
import { api } from '../lib/api';

/**
 * 2FA enrollment + management page.
 *
 * Flow:
 *   1. /api/2fa/status — determines what UI to show.
 *   2. If not enrolled, POST /api/2fa/enroll → render the otpauth URI as a
 *      QR code, show backup codes ONCE, ask for first verification code.
 *   3. POST /api/2fa/complete with the code → enrolled.
 *   4. If enrolled, show backup-code count + a Disable button (requires
 *      password re-auth).
 *
 * We render the QR as an <img> via a public chart server (Google Charts has
 * been deprecated; we use qrserver.com) ONLY for visual scanning. The same
 * `otpauth://` URI is shown as text below so power-users can paste into a
 * password manager directly without QR.
 *
 * No external QR library — keeps the bundle small.
 */
export function TwoFactor() {
  const [status, setStatus] = useState<{ enrolled: boolean; required: boolean; backup_codes_remaining: number } | null>(null);
  const [enrollment, setEnrollment] = useState<{ secret_b32: string; otpauth_uri: string; backup_codes: string[] } | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [disablePassword, setDisablePassword] = useState('');
  const [showDisable, setShowDisable] = useState(false);

  const refresh = async () => {
    try { setStatus(await api.twoFaStatus()); } catch (e: any) { setError(e.message); }
  };

  useEffect(() => { refresh(); }, []);

  async function startEnroll() {
    setError(null); setSuccess(null); setBusy(true);
    try {
      const r = await api.twoFaEnroll();
      setEnrollment(r);
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  async function complete() {
    if (!/^\d{6}$/.test(verifyCode)) { setError('Enter the 6-digit code from your authenticator app.'); return; }
    setError(null); setBusy(true);
    try {
      await api.twoFaComplete(verifyCode);
      setSuccess('2FA enabled. Store your backup codes somewhere safe — they will not be shown again.');
      setEnrollment(null); setVerifyCode('');
      await refresh();
    } catch (e: any) {
      setError(`Verification failed: ${e.message}`);
    } finally { setBusy(false); }
  }

  async function disable() {
    if (!disablePassword) { setError('Confirm your password to disable 2FA.'); return; }
    setError(null); setBusy(true);
    try {
      await api.twoFaDisable(disablePassword);
      setSuccess('2FA disabled.');
      setShowDisable(false); setDisablePassword('');
      await refresh();
    } catch (e: any) {
      setError(`Disable failed: ${e.message}`);
    } finally { setBusy(false); }
  }

  if (!status) return <div className="muted">Loading…</div>;

  return (
    <div className="page">
      <h1>Two-factor authentication</h1>
      <p className="muted">
        FedRAMP 20x KSI-IAM-MFA requires multi-factor authentication for every human user.
        This page lets you enroll a TOTP authenticator (Authy, 1Password, Google Authenticator, etc.).
      </p>

      {error && <div className="alert error">{error}</div>}
      {success && <div className="alert success">{success}</div>}

      {!status.enrolled && !enrollment && (
        <div className="card">
          <p>2FA is NOT currently enabled on your account.</p>
          <button className="primary" disabled={busy} onClick={startEnroll}>
            Begin enrollment
          </button>
        </div>
      )}

      {enrollment && (
        <div className="card">
          <h2>1. Scan this QR with your authenticator</h2>
          <img
            alt="otpauth QR"
            src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(enrollment.otpauth_uri)}`}
            style={{ width: 200, height: 200, border: '1px solid #ddd', padding: 4, background: 'white' }}
          />
          <p>Or paste this URI directly into your password manager:</p>
          <pre className="break-anywhere">{enrollment.otpauth_uri}</pre>

          <h2>2. Save these backup codes</h2>
          <p>Each code can be used ONCE if you lose access to your authenticator. They will not be shown again.</p>
          <pre style={{ background: '#f8f8f8', padding: 12, fontFamily: 'ui-monospace, monospace' }}>
            {enrollment.backup_codes.join('\n')}
          </pre>
          <button className="ghost" onClick={() => {
            const blob = new Blob([enrollment.backup_codes.join('\n') + '\n'], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'fedramp-20x-tracker-backup-codes.txt';
            a.click(); URL.revokeObjectURL(url);
          }}>Download as .txt</button>

          <h2>3. Enter the current 6-digit code from your authenticator</h2>
          <input
            type="text"
            inputMode="numeric"
            autoFocus
            maxLength={6}
            placeholder="123456"
            value={verifyCode}
            onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ''))}
            style={{ fontSize: 24, letterSpacing: 4, width: 160 }}
          />
          <div style={{ marginTop: 12 }}>
            <button className="primary" disabled={busy} onClick={complete}>Verify and enable</button>
            <button className="ghost" disabled={busy} onClick={() => { setEnrollment(null); setVerifyCode(''); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {status.enrolled && (
        <div className="card">
          <p><strong>2FA is enabled.</strong></p>
          <p>Backup codes remaining: <strong>{status.backup_codes_remaining}</strong></p>
          {status.backup_codes_remaining <= 2 && (
            <div className="alert warning">
              You have only {status.backup_codes_remaining} backup code(s) left. Consider re-enrolling to generate a fresh set.
            </div>
          )}
          {!showDisable ? (
            <button className="ghost" onClick={() => setShowDisable(true)}>Disable 2FA</button>
          ) : (
            <div>
              <p>Confirm your password to disable 2FA:</p>
              <input type="password" placeholder="Password" value={disablePassword} onChange={(e) => setDisablePassword(e.target.value)} />
              <div style={{ marginTop: 8 }}>
                <button className="danger" disabled={busy} onClick={disable}>Confirm disable</button>
                <button className="ghost" disabled={busy} onClick={() => { setShowDisable(false); setDisablePassword(''); }}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
