import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { compensatingControlApi } from '../lib/compensating-control-api';
import {
  MIN_DESCRIPTION,
  canSubmitControlForm,
  descriptionRemaining,
  validateControlForm,
  type CompensatingControlFormState,
} from '../lib/compensating-control-view';

/**
 * LOOP-B.B4 — Create a draft compensating control. Client-side validation mirrors
 * the server (5–200 char title, ≥200 char description, ≥1 NIST control id). NIST
 * ids validate against the published catalog server-side on POST; invalid ids
 * return a 400 naming the offending value. The server signs the canonical payload.
 */
export function CompensatingControlCreate() {
  const nav = useNavigate();
  const [s, setS] = useState<CompensatingControlFormState>({
    title: '', description: '', nist_control_ids: [], evidence_url: '', expiration_date: '',
  });
  const [nistText, setNistText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const set = (patch: Partial<CompensatingControlFormState>) => setS((prev) => ({ ...prev, ...patch }));
  const problems = validateControlForm(s);
  const remaining = descriptionRemaining(s.description);

  function syncNistIds(text: string) {
    setNistText(text);
    set({ nist_control_ids: text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean) });
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setBusy(true);
    try {
      const { compensating_control } = await compensatingControlApi.create({
        title: s.title.trim(),
        description: s.description,
        nist_control_ids: s.nist_control_ids,
        evidence_url: s.evidence_url.trim() || undefined,
        expiration_date: s.expiration_date ? new Date(s.expiration_date).toISOString() : undefined,
      });
      nav(`/compensating-controls/${compensating_control.uuid}`);
    } catch (e: any) { setError(e.message); }
    finally { setBusy(false); }
  }

  return (
    <div>
      <h1>New compensating control</h1>
      {error && <div className="alert error">{error}</div>}
      <form onSubmit={submit} style={{ maxWidth: 640 }}>
        <label>Title (5–200 chars)<input value={s.title} onChange={(e) => set({ title: e.target.value })} /></label>
        <label>
          Description{' '}
          <span className="muted" style={{ color: remaining > 0 ? 'crimson' : undefined }}>
            ({s.description.length}/{MIN_DESCRIPTION}{remaining > 0 ? `, ${remaining} more` : ' ✓'})
          </span>
          <textarea rows={6} value={s.description} onChange={(e) => set({ description: e.target.value })} />
        </label>
        <label>
          NIST 800-53 control ids (comma / space separated; base <code>AC-2</code> or enhancement <code>AC-2(3)</code>)
          <input value={nistText} onChange={(e) => syncNistIds(e.target.value)} placeholder="AC-2, AC-2(3), SC-7" />
        </label>
        <label>Evidence URL (optional)<input value={s.evidence_url} onChange={(e) => set({ evidence_url: e.target.value })} placeholder="https://runbooks.example/…" /></label>
        <label>Expiration / annual-review date (optional)
          <input type="date" value={s.expiration_date.slice(0, 10)} onChange={(e) => set({ expiration_date: e.target.value })} />
        </label>
        {!s.expiration_date && <p className="muted" style={{ fontSize: 12 }}>Consider setting an annual review date so the control is re-validated each year.</p>}

        {problems.length > 0 && (
          <ul className="muted" style={{ fontSize: 12 }}>{problems.map((p, i) => <li key={i}>{p}</li>)}</ul>
        )}
        <div style={{ marginTop: 12 }}>
          <button className="primary" type="submit" disabled={busy || !canSubmitControlForm(s)}>Create draft</button>
          <button className="ghost" type="button" onClick={() => nav('/compensating-controls')}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
