import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { riskAcceptanceApi, type RiskAcceptance, type AuditRow } from '../lib/risk-acceptance-api';
import { canApproveAcceptance, canRevokeAcceptance } from '../lib/risk-acceptance-view';

/**
 * LOOP-B.B3 — Per-acceptance detail: signed-payload viewer + audit history +
 * role-gated Approve (ao/admin) / Revoke (iso/ao/admin) CTAs + signature re-verify.
 */
export function RiskAcceptanceDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [acc, setAcc] = useState<RiskAcceptance | null>(null);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    if (!id) return;
    setError(null);
    try {
      const r = await riskAcceptanceApi.detail(id);
      setAcc(r.acceptance);
      setAudit(r.audit);
    } catch (e: any) { setError(e.message); }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [id]);

  async function approve() {
    if (!id) return;
    setBusy(true); setError(null);
    try { await riskAcceptanceApi.approve(id); await reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function revoke() {
    if (!id) return;
    const reason = window.prompt('Revocation reason (min 30 chars):') ?? '';
    if (reason.trim().length < 30) { setError('Revocation reason must be at least 30 characters.'); return; }
    setBusy(true); setError(null);
    try { await riskAcceptanceApi.revoke(id, reason.trim()); await reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function verify() {
    if (!id) return;
    setError(null);
    try {
      const v = await riskAcceptanceApi.verify(id);
      setVerifyResult(`Signature ${v.valid ? 'VALID' : 'INVALID'}${v.approval_valid == null ? '' : `; approval ${v.approval_valid ? 'VALID' : 'INVALID'}`} (key ${v.signing_key_id})`);
    } catch (e: any) { setError(e.message); }
  }

  if (error && !acc) return <div className="alert error">{error}</div>;
  if (!acc) return <div className="muted">Loading…</div>;

  return (
    <div>
      <p><Link to="/risk-acceptance">← Risk acceptances</Link></p>
      <h1>{acc.ksi_id} / <code>{acc.rule}</code></h1>
      <p className="muted">Status: <b>{acc.status}</b> · type {acc.acceptance_type} · expires {acc.expiration_date.slice(0, 10)}</p>
      {error && <div className="alert error">{error}</div>}

      <div style={{ margin: '12px 0' }}>
        {canApproveAcceptance(role, acc.status) && <button className="primary" disabled={busy} onClick={approve}>Approve (AO)</button>}
        {canRevokeAcceptance(role, acc.status) && <button className="ghost" disabled={busy} onClick={revoke}>Revoke</button>}
        <button className="ghost" onClick={verify}>Verify signature</button>
      </div>
      {verifyResult && <div className="alert">{verifyResult}</div>}

      <h3>Business justification</h3>
      <p style={{ whiteSpace: 'pre-wrap' }}>{acc.business_justification}</p>

      <h3>Compensating controls</h3>
      {acc.compensating_control_uuids.length === 0 ? <p className="muted">None linked.</p>
        : <ul>{acc.compensating_control_uuids.map((c) => <li key={c}><code>{c}</code></li>)}</ul>}

      <h3>Signed record</h3>
      <pre style={{ overflowX: 'auto' }}>{JSON.stringify({
        uuid: acc.uuid, finding_uuid: acc.finding_uuid, accepted_by_user_id: acc.accepted_by_user_id,
        accepted_at: acc.accepted_at, expiration_date: acc.expiration_date, acceptance_type: acc.acceptance_type,
        signature: acc.signature, signing_key_id: acc.signing_key_id,
        approved_by_user_id: acc.approved_by_user_id, approved_at: acc.approved_at, approval_signature: acc.approval_signature,
      }, null, 2)}</pre>

      <h3>Audit history</h3>
      <table>
        <thead><tr><th>When</th><th>Field</th><th>Old</th><th>New</th><th>By</th></tr></thead>
        <tbody>
          {audit.map((a, i) => (
            <tr key={i}><td>{a.changed_at}</td><td>{a.field}</td><td>{a.old_value ?? ''}</td><td>{a.new_value ?? ''}</td><td>{a.user_id ?? 'system'}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
