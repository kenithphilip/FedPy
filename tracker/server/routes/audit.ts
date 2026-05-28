/**
 * Audit log search API.
 *
 *   GET    /api/audit?actor=<userId>&action=<field>&item=<id>&from=<iso>&to=<iso>&limit=<n>
 *
 * Permission: `read:audit_log` (auditor + admin).
 *
 * The audit log is append-only; this endpoint only reads.
 *
 * Filter semantics:
 *   actor       — user_id (exact). Use 0 for "system / api token".
 *   action      — field name (e.g. "role", "status", "domain_assigned"). Exact match.
 *   item        — item_id (e.g. "user:7", "KSI-IAM-MFA"). Substring match.
 *   item_type   — "requirement" | "indicator" | "rbac". Exact match.
 *   from        — ISO datetime (UTC). Inclusive lower bound on changed_at.
 *   to          — ISO datetime (UTC). Inclusive upper bound.
 *   limit       — max rows to return (default 200, max 5000).
 *   offset      — for pagination.
 *
 * Returns:
 *   { rows: [...], total: <count of matching rows> }
 *
 * CSV export:
 *   GET /api/audit.csv with the same query parameters returns text/csv.
 */
import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';
import { requirePermission } from '../rbac.ts';

export const auditRoutes = new Hono();

auditRoutes.use('*', requireAuth);
auditRoutes.use('*', requirePermission('read:audit_log'));

interface Filters {
  actor?: number | null;
  action?: string;
  item?: string;
  item_type?: string;
  from?: string;
  to?: string;
  limit: number;
  offset: number;
}

/** Parse an integer param; falls back to `fallback` if missing/NaN/out-of-bounds. */
function parseInt0(raw: string | null, fallback: number, min: number, max: number): number {
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function parseFilters(q: URLSearchParams): Filters {
  const actorRaw = q.get('actor');
  // actor: undefined → no filter; null → filter to system/null actors;
  //        finite integer → filter to that user id. Reject NaN / non-integer.
  let actor: number | null | undefined;
  if (actorRaw == null) {
    actor = undefined;
  } else if (actorRaw === '') {
    actor = null;
  } else {
    const n = Number(actorRaw);
    actor = Number.isFinite(n) && Number.isInteger(n) ? n : undefined;
  }
  return {
    actor,
    action: q.get('action') || undefined,
    item: q.get('item') || undefined,
    item_type: q.get('item_type') || undefined,
    from: q.get('from') || undefined,
    to: q.get('to') || undefined,
    limit: parseInt0(q.get('limit'), 200, 1, 5000),
    offset: parseInt0(q.get('offset'), 0, 0, Number.MAX_SAFE_INTEGER),
  };
}

function buildSql(f: Filters): { where: string; params: any[] } {
  const conds: string[] = [];
  const params: any[] = [];
  if (f.actor !== undefined) {
    if (f.actor === null) {
      conds.push('a.user_id IS NULL');
    } else {
      conds.push('a.user_id = ?'); params.push(f.actor);
    }
  }
  if (f.action) { conds.push('a.field = ?'); params.push(f.action); }
  if (f.item) { conds.push('a.item_id LIKE ?'); params.push(`%${f.item}%`); }
  if (f.item_type) { conds.push('a.item_type = ?'); params.push(f.item_type); }
  if (f.from) { conds.push('a.changed_at >= ?'); params.push(f.from); }
  if (f.to) { conds.push('a.changed_at <= ?'); params.push(f.to); }
  return { where: conds.length ? 'WHERE ' + conds.join(' AND ') : '', params };
}

auditRoutes.get('/', (c) => {
  const url = new URL(c.req.url);
  const f = parseFilters(url.searchParams);
  const { where, params } = buildSql(f);

  const total = (db().prepare(
    `SELECT COUNT(*) AS c FROM audit_log a ${where}`,
  ).get(...params) as any).c as number;

  const rows = db().prepare(
    `SELECT a.id, a.user_id, u.email AS user_email, u.name AS user_name,
            a.item_id, a.item_type, a.field, a.old_value, a.new_value, a.changed_at
     FROM audit_log a
     LEFT JOIN users u ON u.id = a.user_id
     ${where}
     ORDER BY a.changed_at DESC, a.id DESC
     LIMIT ? OFFSET ?`,
  ).all(...params, f.limit, f.offset);

  return c.json({ rows, total, limit: f.limit, offset: f.offset });
});

auditRoutes.get('/csv', (c) => {
  const url = new URL(c.req.url);
  const f = parseFilters(url.searchParams);
  const { where, params } = buildSql(f);
  const rows = db().prepare(
    `SELECT a.changed_at, u.email AS user_email, u.name AS user_name,
            a.item_id, a.item_type, a.field, a.old_value, a.new_value
     FROM audit_log a
     LEFT JOIN users u ON u.id = a.user_id
     ${where}
     ORDER BY a.changed_at DESC, a.id DESC
     LIMIT ?`,
  ).all(...params, f.limit) as Array<Record<string, any>>;

  const header = ['changed_at', 'user_email', 'user_name', 'item_id', 'item_type', 'field', 'old_value', 'new_value'];
  const esc = (v: any) => {
    if (v == null) return '';
    const s = String(v);
    if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  };
  const lines = [header.join(',')];
  for (const r of rows) lines.push(header.map((h) => esc(r[h])).join(','));
  return c.body(lines.join('\n'), 200, {
    'content-type': 'text/csv; charset=utf-8',
    'content-disposition': `attachment; filename="audit-log-${new Date().toISOString().slice(0, 10)}.csv"`,
  });
});

/**
 * Distinct facet values, useful for populating filter dropdowns in the UI.
 */
auditRoutes.get('/facets', (c) => {
  const actions = (db().prepare(`SELECT DISTINCT field FROM audit_log ORDER BY field`).all() as Array<{ field: string }>).map((r) => r.field);
  const itemTypes = (db().prepare(`SELECT DISTINCT item_type FROM audit_log ORDER BY item_type`).all() as Array<{ item_type: string }>).map((r) => r.item_type);
  const actors = db().prepare(`
    SELECT DISTINCT u.id, u.email, u.name FROM audit_log a JOIN users u ON u.id = a.user_id ORDER BY u.email
  `).all();
  return c.json({ actions, item_types: itemTypes, actors });
});
