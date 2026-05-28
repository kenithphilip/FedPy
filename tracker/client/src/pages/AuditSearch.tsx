import { useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';

/**
 * Audit-log search page. Available to roles with `read:audit_log` permission
 * (auditor + admin). The sidebar link in App.tsx is gated to those roles.
 *
 * Filters update on every change (debounced via React state batching). The
 * CSV-export button generates a download URL with the same filter params.
 */
interface Filters {
  actor: string;       // user id or "" for null actors
  action: string;
  item: string;
  item_type: string;
  from: string;        // ISO datetime
  to: string;          // ISO datetime
  limit: string;
  offset: string;
}

const EMPTY: Filters = { actor: '', action: '', item: '', item_type: '', from: '', to: '', limit: '200', offset: '0' };

export function AuditSearch() {
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [rows, setRows] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [facets, setFacets] = useState<{ actions: string[]; item_types: string[]; actors: any[] }>({ actions: [], item_types: [], actors: [] });

  // Track each search by a monotonic ID; if a later search starts before an
  // earlier one resolves, the stale response is discarded. Prevents the
  // race where rapidly changing filters could leave the table showing
  // results for an old filter set.
  const requestSeqRef = useRef(0);
  const search = async () => {
    const mySeq = ++requestSeqRef.current;
    setLoading(true); setError(null);
    try {
      const params: Record<string, string | number | undefined> = {};
      // Actor filter: '' = no filter, '0' = filter to system/API token (null user_id),
      // any other value = filter to that user id.
      if (filters.actor === '0') params.actor = '';
      else if (filters.actor !== '') params.actor = filters.actor;
      if (filters.action) params.action = filters.action;
      if (filters.item) params.item = filters.item;
      if (filters.item_type) params.item_type = filters.item_type;
      if (filters.from) params.from = filters.from;
      if (filters.to) params.to = filters.to;
      params.limit = Number(filters.limit) || 200;
      params.offset = Number(filters.offset) || 0;
      const r = await api.auditSearch(params);
      if (mySeq !== requestSeqRef.current) return;  // stale; another request superseded us
      setRows(r.rows);
      setTotal(r.total);
    } catch (e: any) {
      if (mySeq !== requestSeqRef.current) return;
      setError(e?.message ?? 'Search failed');
    } finally {
      if (mySeq === requestSeqRef.current) setLoading(false);
    }
  };

  useEffect(() => { api.auditFacets().then(setFacets).catch(() => {}); }, []);
  useEffect(() => { search(); }, [filters]);

  function update<K extends keyof Filters>(key: K, value: Filters[K]) {
    setFilters((f) => ({ ...f, [key]: value, offset: key === 'offset' ? value : '0' }));
  }

  function csvUrl(): string {
    const params: Record<string, string | number | undefined> = { ...filters };
    return api.auditCsvUrl(params);
  }

  const limitN = Number(filters.limit) || 200;
  const offsetN = Number(filters.offset) || 0;
  const pageCount = Math.ceil(total / limitN);
  const pageIdx = Math.floor(offsetN / limitN);

  return (
    <div className="page">
      <h1>Audit log</h1>
      <p className="muted">
        Every state change in the tracker is recorded here. Use the filters below to narrow your search;
        export to CSV for offline review.
      </p>

      {error && <div className="alert error">{error}</div>}

      <div className="filters" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
        <label>
          Actor
          <select value={filters.actor} onChange={(e) => update('actor', e.target.value)}>
            <option value="">All</option>
            <option value="0">System / API token (null actor)</option>
            {facets.actors.map((a) => (
              <option key={a.id} value={String(a.id)}>{a.name} &lt;{a.email}&gt;</option>
            ))}
          </select>
        </label>
        <label>
          Action
          <select value={filters.action} onChange={(e) => update('action', e.target.value)}>
            <option value="">All</option>
            {facets.actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
        </label>
        <label>
          Item type
          <select value={filters.item_type} onChange={(e) => update('item_type', e.target.value)}>
            <option value="">All</option>
            {facets.item_types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>
          Item ID contains
          <input type="text" placeholder="e.g. KSI-IAM" value={filters.item} onChange={(e) => update('item', e.target.value)} />
        </label>
        <label>
          From
          <input type="datetime-local" value={filters.from} onChange={(e) => update('from', e.target.value)} />
        </label>
        <label>
          To
          <input type="datetime-local" value={filters.to} onChange={(e) => update('to', e.target.value)} />
        </label>
        <label>
          Limit
          <input type="number" min={1} max={5000} value={filters.limit} onChange={(e) => update('limit', e.target.value)} />
        </label>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8 }}>
          <button className="ghost" onClick={() => setFilters(EMPTY)}>Reset filters</button>
          <a className="primary" href={csvUrl()} download>Export CSV</a>
        </div>
      </div>

      <div className="muted" style={{ margin: '12px 0' }}>
        {loading ? 'Loading…' : `${total.toLocaleString()} event(s) match · showing ${rows.length}`}
      </div>

      <table className="table" style={{ width: '100%', fontSize: 13 }}>
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Item</th>
            <th>Type</th>
            <th>Field</th>
            <th>Old → New</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td><time dateTime={r.changed_at}>{r.changed_at}</time></td>
              <td>{r.user_name ? `${r.user_name} <${r.user_email}>` : <span className="muted">system / API</span>}</td>
              <td><code>{r.item_id}</code></td>
              <td>{r.item_type}</td>
              <td>{r.field}</td>
              <td>
                <span className="muted">{r.old_value ?? '∅'}</span>
                {' → '}
                <span>{r.new_value ?? '∅'}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {pageCount > 1 && (
        <div className="pagination" style={{ marginTop: 12, display: 'flex', gap: 8 }}>
          <button className="ghost" disabled={offsetN === 0} onClick={() => update('offset', String(Math.max(0, offsetN - limitN)))}>← Prev</button>
          <span className="muted">Page {pageIdx + 1} of {pageCount}</span>
          <button className="ghost" disabled={offsetN + limitN >= total} onClick={() => update('offset', String(offsetN + limitN))}>Next →</button>
        </div>
      )}
    </div>
  );
}
