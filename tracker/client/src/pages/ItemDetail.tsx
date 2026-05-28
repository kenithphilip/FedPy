import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useParams } from 'react-router-dom';
import { useEffect, useRef, useState } from 'react';
import { api, isApiError } from '../lib/api';
import {
  ApplicabilityPill,
  KeywordPill,
  StatusPill,
  STATUSES,
  STATUS_LABEL,
  annotateTerms,
} from '../lib/formatting';

interface Props { kind: 'requirement' | 'indicator'; }

export function ItemDetail({ kind }: Props) {
  const { id = '' } = useParams();
  const qc = useQueryClient();

  const { data, isLoading } = useQuery<any>({
    queryKey: [kind, id],
    queryFn: () =>
      (kind === 'requirement' ? api.requirementDetail(id) : api.indicatorDetail(id)) as Promise<any>,
  });
  const { data: defs } = useQuery({ queryKey: ['definitions'], queryFn: () => api.definitions() });
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: () => api.users() });

  const item = (data as any)?.[kind] as any | undefined;
  const history = (data as any)?.history as any[] | undefined;

  const [form, setForm] = useState({
    status: 'not_started',
    owner_user_id: '',
    owner_text: '',
    notes: '',
    evidence_url: '',
    last_reviewed: '',
  });

  useEffect(() => {
    if (!item) return;
    setForm({
      status: item.status ?? 'not_started',
      owner_user_id: item.owner_user_id != null ? String(item.owner_user_id) : '',
      owner_text: item.owner_text ?? '',
      notes: item.notes ?? '',
      evidence_url: item.evidence_url ?? '',
      last_reviewed: item.last_reviewed ?? '',
    });
  }, [item?.id, item?.updated_at]);

  const save = useMutation({
    mutationFn: () => api.patchItem(kind, id, {
      status: form.status,
      owner_user_id: form.owner_user_id ? Number(form.owner_user_id) : null,
      owner_text: form.owner_text || null,
      notes: form.notes || null,
      evidence_url: form.evidence_url || null,
      last_reviewed: form.last_reviewed || null,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [kind, id] });
      qc.invalidateQueries({ queryKey: ['dashboard'] });
      qc.invalidateQueries({ queryKey: ['requirements'] });
      qc.invalidateQueries({ queryKey: ['indicators'] });
      qc.invalidateQueries({ queryKey: ['crosswalk'] });
    },
  });

  if (isLoading || !item) return <div className="muted">Loading…</div>;

  const termObjs = (defs?.definitions ?? []).filter((d: any) =>
    Array.isArray(item.terms) && item.terms.includes(d.term)
  );

  return (
    <div>
      <p className="muted small">
        <Link to={kind === 'requirement' ? '/requirements' : '/indicators'}>← Back</Link>
      </p>

      <div className="row" style={{ gap: 10, marginBottom: 8 }}>
        <span className="mono" style={{ fontSize: 18, fontWeight: 600 }}>{item.id}</span>
        {kind === 'requirement' && <KeywordPill kw={item.primary_key_word} />}
        {kind === 'requirement' && <ApplicabilityPill applicability={item.applicability} />}
        <span className="spacer" />
        <StatusPill status={item.status} />
      </div>
      {item.name && <h1 className="h1" style={{ marginTop: 4 }}>{item.name}</h1>}

      <div className="grid cols-2">
        <div>
          <div className="card">
            <strong>Statement</strong>
            <p style={{ marginTop: 6 }}>{annotateTerms(item.statement, termObjs)}</p>

            {Array.isArray(item.following_information) && item.following_information.length > 0 && (
              <ul>{item.following_information.map((s: string, i: number) => <li key={i}>{s}</li>)}</ul>
            )}

            {item.note && <p className="muted small" style={{ marginTop: 8 }}><strong>Note:</strong> {item.note}</p>}

            {Array.isArray(item.examples) && item.examples.length > 0 && (
              <>
                <strong>Examples</strong>
                <ul>{item.examples.map((ex: any, i: number) => (
                  <li key={i}>{typeof ex === 'string' ? ex : JSON.stringify(ex)}</li>
                ))}</ul>
              </>
            )}

            {item.raw?.varies_by_level && (
              <>
                <strong>Varies by impact level</strong>
                <pre className="mono small" style={{ background: 'var(--panel-2)', padding: 10, borderRadius: 6, overflow: 'auto' }}>
                  {JSON.stringify(item.raw.varies_by_level, null, 2)}
                </pre>
              </>
            )}
          </div>

          {kind === 'indicator' && Array.isArray(item.controls) && item.controls.length > 0 && (
            <div className="card">
              <strong>NIST 800-53 controls</strong>
              <p className="mono small" style={{ marginTop: 6 }}>{item.controls.join(', ')}</p>
            </div>
          )}

          {kind === 'requirement' && (
            <div className="card">
              <div className="row small muted">
                <span>Process: <strong>{item.process_id}</strong></span>
                <span>·</span>
                <span>Actor: <strong>{item.actor_label}</strong></span>
                {item.fka && <><span>·</span><span>FKA: <span className="mono">{item.fka}</span></span></>}
              </div>
            </div>
          )}

          {history && history.length > 0 && (
            <div className="card">
              <strong>History</strong>
              <table className="table">
                <tbody>
                  {history.map((h: any, i: number) => (
                    <tr key={i}>
                      <td className="small muted" style={{ whiteSpace: 'nowrap' }}>{h.changed_at}</td>
                      <td className="small">{h.user_name ?? '?'}</td>
                      <td className="small mono">{h.field}</td>
                      <td className="small muted">{h.old_value ?? '∅'} → {h.new_value ?? '∅'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div>
          <div className="card">
            <strong>Tracker state</strong>

            <label style={{ marginTop: 10 }}>Status</label>
            <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
            </select>

            <label style={{ marginTop: 10 }}>Owner (user)</label>
            <select value={form.owner_user_id} onChange={(e) => setForm({ ...form, owner_user_id: e.target.value })}>
              <option value="">— none —</option>
              {users?.users.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
            </select>

            <label style={{ marginTop: 10 }}>Owner (free text / team)</label>
            <input value={form.owner_text} onChange={(e) => setForm({ ...form, owner_text: e.target.value })}
                   placeholder="e.g. Platform Security" />

            <label style={{ marginTop: 10 }}>Evidence URL</label>
            <input value={form.evidence_url} onChange={(e) => setForm({ ...form, evidence_url: e.target.value })}
                   placeholder="https://…" />

            <label style={{ marginTop: 10 }}>Last reviewed</label>
            <input type="date" value={form.last_reviewed}
                   onChange={(e) => setForm({ ...form, last_reviewed: e.target.value })} />

            <label style={{ marginTop: 10 }}>Notes</label>
            <textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })}
                      placeholder="implementation notes, decisions, blockers…" />

            <div className="row" style={{ marginTop: 12 }}>
              <button onClick={() => save.mutate()} disabled={save.isPending}>
                {save.isPending ? 'Saving…' : 'Save'}
              </button>
              {save.isSuccess && <span className="small" style={{ color: 'var(--ok)' }}>Saved</span>}
              {save.isError && <span className="small" style={{ color: 'var(--err)' }}>{(save.error as Error).message}</span>}
              <span className="spacer" />
              {item.updated_at && (
                <span className="muted small">Updated {item.updated_at} by {item.updated_by_name ?? '?'}</span>
              )}
            </div>
          </div>

          <AttachmentsPanel itemId={id} itemType={kind} />
        </div>
      </div>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function AttachmentsPanel({ itemId, itemType }: { itemId: string; itemType: 'requirement' | 'indicator' }) {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [truncatedWarning, setTruncatedWarning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const key = ['attachments', itemType, itemId];
  const { data, isLoading } = useQuery({ queryKey: key, queryFn: () => api.attachmentsList(itemId, itemType) });

  const upload = useMutation({
    mutationFn: (file: File) => api.attachmentUpload(itemId, itemType, file),
    onSuccess: (res) => {
      setError(null);
      setTruncatedWarning(
        res.filename_truncated
          ? `The filename was longer than 200 characters and was stored as "${res.filename}".`
          : null,
      );
      if (fileRef.current) fileRef.current.value = '';
      qc.invalidateQueries({ queryKey: key });
    },
    onError: (e: unknown) => {
      setTruncatedWarning(null);
      setError(
        isApiError(e) && e.status === 415 ? 'That file type is not allowed.'
        : isApiError(e) && e.status === 413 ? 'That file is too large.'
        : (e as Error).message,
      );
    },
  });

  const del = useMutation({
    mutationFn: (id: number) => api.attachmentDelete(itemId, itemType, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
  });

  const attachments = data?.attachments ?? [];

  return (
    <div className="card">
      <strong>Evidence attachments</strong>

      <div className="row" style={{ marginTop: 10, gap: 8, alignItems: 'center' }}>
        <input
          ref={fileRef}
          type="file"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) upload.mutate(f);
          }}
          disabled={upload.isPending}
        />
        {upload.isPending && <span className="muted small">Uploading…</span>}
      </div>

      {truncatedWarning && (
        <p className="small" style={{ color: 'var(--warn, #b8860b)', marginTop: 8 }}>⚠ {truncatedWarning}</p>
      )}
      {error && (
        <p className="small" style={{ color: 'var(--err)', marginTop: 8 }}>{error}</p>
      )}

      {isLoading ? (
        <p className="muted small" style={{ marginTop: 8 }}>Loading…</p>
      ) : attachments.length === 0 ? (
        <p className="muted small" style={{ marginTop: 8 }}>No attachments yet.</p>
      ) : (
        <table className="table" style={{ marginTop: 8 }}>
          <tbody>
            {attachments.map((a) => (
              <tr key={a.id}>
                <td className="small">
                  <a href={api.attachmentDownloadUrl(a.id)} target="_blank" rel="noreferrer">{a.filename}</a>
                </td>
                <td className="small muted" style={{ whiteSpace: 'nowrap' }}>{formatBytes(a.bytes)}</td>
                <td className="small muted" style={{ whiteSpace: 'nowrap' }}>{a.uploaded_by_name ?? '?'}</td>
                <td className="small" style={{ textAlign: 'right' }}>
                  <button
                    className="danger"
                    onClick={() => { if (confirm(`Delete ${a.filename}?`)) del.mutate(a.id); }}
                    disabled={del.isPending}
                  >Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
