import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { compensatingControlApi, type CompensatingControl, type AuditRow, type LinkedAcceptance } from '../lib/compensating-control-api';
import { MIN_RETIREMENT_REASON, canActivateControl, canRetireControl } from '../lib/compensating-control-view';

/**
 * LOOP-B.B4 — Per-control detail: signed-payload viewer + linked acceptances +
 * audit history + role-gated Activate (ao/admin, draft) / Retire (iso/ao/admin,
 * active) CTAs + signature re-verify.
 */
export function CompensatingControlDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const role = (user?.role as string) ?? 'viewer';
  const [cc, setCc] = useState<CompensatingControl | null>(null);
  const [links, setLinks] = useState<LinkedAcceptance[]>([]);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    if (!id) return;
    setError(null);
    try {
      const r = await compensatingControlApi.detail(id);
      setCc(r.compensating_control);
      setLinks(r.linked_acceptances);
      setAudit(r.audit);
    } catch (e: any) { setError(e.message); }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [id]);

  async function activate() {
    if (!id) return;
    setBusy(true); setError(null);
    try { await compensatingControlApi.activate(id); await reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function retire() {
    if (!id) return;
    const reason = window.prompt(`Retirement reason (min ${MIN_RETIREMENT_REASON} chars):`) ?? '';
    if (reason.trim().length < MIN_RETIREMENT_REASON) { setError(`Retirement reason must be at least ${MIN_RETIREMENT_REASON} characters.`); return; }
    setBusy(true); setError(null);
    try { await compensatingControlApi.retire(id, reason.trim()); await reload(); }
    catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function verify() {
    if (!id) return;
    setError(null);
    try {
      const v = await compensatingControlApi.verify(id);
      setVerifyResult(`Signature ${v.valid ? 'VALID' : 'INVALID'}${v.activation_valid == null ? '' : `; activation ${v.activation_valid ? 'VALID' : 'INVALID'}`} (key ${v.signing_key_id})`);
    } catch (e: any) { setError(e.message); }
  }

  if (error && !cc) return <div className="alert error">{error}</div>;
  if (!cc) return <div className="muted">Loading…</div>;

  return (
    <div>
      <p><Link to="/compensating-controls">← Compensating controls</Link></p>
      <h1>{cc.title}</h1>
      <p className="muted">Status: <b>{cc.status}</b> · expires {cc.expiration_date ? cc.expiration_date.slice(0, 10) : 'never'}</p>
      {error && <div className="alert error">{error}</div>}

      <div style={{ margin: '12px 0' }}>
        {canActivateControl(role, cc.status) && <button className="primary" disabled={busy} onClick={activate}>Activate (AO)</button>}
        {canRetireControl(role, cc.status) && <button className="ghost" disabled={busy} onClick={retire}>Retire</button>}
        <button className="ghost" onClick={verify}>Verify signature</button>
      </div>
      {verifyResult && <div className="alert">{verifyResult}</div>}

      <h3>Description</h3>
      <p style={{ whiteSpace: 'pre-wrap' }}>{cc.description}</p>

      <h3>NIST 800-53 controls</h3>
      <ul>{cc.nist_control_ids.map((c) => <li key={c}><code>{c}</code></li>)}</ul>

      {cc.evidence_url && <p>Evidence: <a href={cc.evidence_url} target="_blank" rel="noreferrer">{cc.evidence_url}</a>{cc.evidence_sha256 ? <> · sha256 <code>{cc.evidence_sha256.slice(0, 16)}…</code></> : null}</p>}

      <h3>Linked acceptances</h3>
      {links.length === 0 ? <p className="muted">None reference this control.</p>
        : <ul>{links.map((l) => <li key={l.uuid}><Link to={`/risk-acceptance/${l.uuid}`}>{l.ksi_id} / <code>{l.rule}</code></Link> ({l.status})</li>)}</ul>}

      <h3>Signed record</h3>
      <pre style={{ overflowX: 'auto' }}>{JSON.stringify({
        uuid: cc.uuid, title: cc.title, nist_control_ids: cc.nist_control_ids,
        implemented_by_user_id: cc.implemented_by_user_id, implemented_at: cc.implemented_at,
        evidence_url: cc.evidence_url, evidence_sha256: cc.evidence_sha256,
        signature: cc.signature, signing_key_id: cc.signing_key_id,
        signed_off_by_user_id: cc.signed_off_by_user_id, signed_off_at: cc.signed_off_at, activation_signature: cc.activation_signature,
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
