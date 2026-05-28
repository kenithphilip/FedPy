import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';

export const exportRoutes = new Hono();
exportRoutes.use('*', requireAuth);

function csvEscape(v: unknown): string {
  if (v == null) return '';
  const s = String(v);
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const header = columns.join(',');
  const body = rows.map((r) => columns.map((c) => csvEscape(r[c])).join(',')).join('\n');
  return header + '\n' + body + '\n';
}

interface ExportRow {
  type: 'requirement' | 'indicator';
  id: string;
  process_or_domain: string;
  applicability: string;
  actor_label: string;
  name: string;
  primary_key_word: string;
  statement: string;
  controls: string;
  status: string;
  owner: string;
  notes: string;
  evidence_url: string;
  last_reviewed: string;
  updated_at: string;
}

function fetchExportRows(): ExportRow[] {
  const reqs = db().prepare(`
    SELECT r.id, r.process_id, r.applicability, r.actor_label, r.name, r.primary_key_word, r.statement,
           COALESCE(s.status,'not_started') AS status,
           COALESCE(u.name, s.owner_text, '') AS owner,
           COALESCE(s.notes, '') AS notes,
           COALESCE(s.evidence_url, '') AS evidence_url,
           COALESCE(s.last_reviewed, '') AS last_reviewed,
           COALESCE(s.updated_at, '') AS updated_at
    FROM requirements r
    LEFT JOIN item_state s ON s.item_id = r.id AND s.item_type = 'requirement'
    LEFT JOIN users u ON u.id = s.owner_user_id
    ORDER BY r.process_id, r.id
  `).all() as any[];

  const inds = db().prepare(`
    SELECT i.id, i.domain_id, i.name, i.statement,
           COALESCE(s.status,'not_started') AS status,
           COALESCE(u.name, s.owner_text, '') AS owner,
           COALESCE(s.notes, '') AS notes,
           COALESCE(s.evidence_url, '') AS evidence_url,
           COALESCE(s.last_reviewed, '') AS last_reviewed,
           COALESCE(s.updated_at, '') AS updated_at,
           (SELECT GROUP_CONCAT(control_id, ';')
              FROM indicator_controls
             WHERE indicator_id = i.id) AS controls
    FROM indicators i
    LEFT JOIN item_state s ON s.item_id = i.id AND s.item_type = 'indicator'
    LEFT JOIN users u ON u.id = s.owner_user_id
    ORDER BY i.domain_id, i.id
  `).all() as any[];

  const rows: ExportRow[] = [];
  for (const r of reqs) {
    rows.push({
      type: 'requirement',
      id: r.id,
      process_or_domain: r.process_id,
      applicability: r.applicability,
      actor_label: r.actor_label,
      name: r.name ?? '',
      primary_key_word: r.primary_key_word ?? '',
      statement: r.statement ?? '',
      controls: '',
      status: r.status,
      owner: r.owner,
      notes: r.notes,
      evidence_url: r.evidence_url,
      last_reviewed: r.last_reviewed,
      updated_at: r.updated_at,
    });
  }
  for (const i of inds) {
    rows.push({
      type: 'indicator',
      id: i.id,
      process_or_domain: i.domain_id,
      applicability: '20x',
      actor_label: '',
      name: i.name ?? '',
      primary_key_word: '',
      statement: i.statement ?? '',
      controls: i.controls ?? '',
      status: i.status,
      owner: i.owner,
      notes: i.notes,
      evidence_url: i.evidence_url,
      last_reviewed: i.last_reviewed,
      updated_at: i.updated_at,
    });
  }
  return rows;
}

exportRoutes.get('/export', (c) => {
  const format = (c.req.query('format') ?? 'json').toLowerCase();
  const rows = fetchExportRows();

  if (format === 'csv') {
    const csv = toCsv(rows as any, [
      'type','id','process_or_domain','applicability','actor_label','name','primary_key_word',
      'statement','controls','status','owner','notes','evidence_url','last_reviewed','updated_at',
    ]);
    return new Response(csv, {
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'content-disposition': `attachment; filename="fedramp-tracker-${new Date().toISOString().slice(0,10)}.csv"`,
      },
    });
  }

  return new Response(JSON.stringify({ exported_at: new Date().toISOString(), rows }, null, 2), {
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="fedramp-tracker-${new Date().toISOString().slice(0,10)}.json"`,
    },
  });
});
