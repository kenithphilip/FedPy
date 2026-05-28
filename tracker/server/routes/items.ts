import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';

export const itemRoutes = new Hono();
itemRoutes.use('*', requireAuth);

// ---- Helpers ----

interface ItemState {
  status: string;
  owner_user_id: number | null;
  owner_name: string | null;
  owner_text: string | null;
  notes: string | null;
  evidence_url: string | null;
  last_reviewed: string | null;
  updated_at: string | null;
  updated_by_name: string | null;
}

const REQ_SELECT = `
  SELECT
    r.id, r.process_id, r.applicability, r.actor_label, r.name, r.statement,
    r.primary_key_word, r.note, r.fka,
    r.terms_json, r.affects_json, r.following_info_json, r.examples_json,
    r.timeframe_type, r.timeframe_num,
    COALESCE(s.status, 'not_started') AS status,
    s.owner_user_id,
    ou.name AS owner_name,
    s.owner_text,
    s.notes,
    s.evidence_url,
    s.last_reviewed,
    s.updated_at,
    uu.name AS updated_by_name
  FROM requirements r
  LEFT JOIN item_state s ON s.item_id = r.id AND s.item_type = 'requirement'
  LEFT JOIN users ou ON ou.id = s.owner_user_id
  LEFT JOIN users uu ON uu.id = s.updated_by
`;

const IND_SELECT = `
  SELECT
    i.id, i.domain_id, i.name, i.statement, i.fka,
    COALESCE(s.status, 'not_started') AS status,
    s.owner_user_id,
    ou.name AS owner_name,
    s.owner_text,
    s.notes,
    s.evidence_url,
    s.last_reviewed,
    s.updated_at,
    uu.name AS updated_by_name
  FROM indicators i
  LEFT JOIN item_state s ON s.item_id = i.id AND s.item_type = 'indicator'
  LEFT JOIN users ou ON ou.id = s.owner_user_id
  LEFT JOIN users uu ON uu.id = s.updated_by
`;

function parseJsonFields(row: any, fields: string[]): any {
  for (const f of fields) {
    if (row[f] != null) {
      try { row[f.replace(/_json$/, '')] = JSON.parse(row[f]); } catch {}
    }
    delete row[f];
  }
  return row;
}

// ---- Reference data ----

itemRoutes.get('/meta', (c) => {
  const rows = db().prepare(`SELECT key, value FROM frmr_meta`).all() as any[];
  const meta: Record<string, string> = {};
  for (const r of rows) meta[r.key] = r.value;
  return c.json({ meta });
});

itemRoutes.get('/processes', (c) => {
  const procs = db().prepare(`
    SELECT id, short_name, name, web_name FROM processes WHERE kind = 'FRR' ORDER BY id
  `).all();
  return c.json({ processes: procs });
});

itemRoutes.get('/processes/:id', (c) => {
  const id = c.req.param('id');
  const proc = db().prepare(`SELECT * FROM processes WHERE id = ?`).get(id) as any;
  if (!proc) return c.json({ error: 'not found' }, 404);
  const labels = db().prepare(
    `SELECT label_key, label_name FROM process_labels WHERE process_id = ? ORDER BY label_key`
  ).all(id);
  if (proc.info_json) {
    try { proc.info = JSON.parse(proc.info_json); } catch {}
    delete proc.info_json;
  }
  return c.json({ process: proc, labels });
});

itemRoutes.get('/ksi-domains', (c) => {
  const domains = db().prepare(`
    SELECT id, short_name, name, web_name, theme FROM ksi_domains ORDER BY id
  `).all();
  return c.json({ domains });
});

itemRoutes.get('/definitions', (c) => {
  const rows = db().prepare(`
    SELECT id, term, definition, alts_json, fka FROM definitions ORDER BY term
  `).all() as any[];
  for (const r of rows) parseJsonFields(r, ['alts_json']);
  return c.json({ definitions: rows });
});

// ---- Requirements ----

itemRoutes.get('/requirements', (c) => {
  const process_id = c.req.query('process');
  const applicability = c.req.query('applicability');
  const actor = c.req.query('actor');
  const status = c.req.query('status');
  const owner = c.req.query('owner');
  const q = c.req.query('q');

  const where: string[] = [];
  const params: any[] = [];
  if (process_id)   { where.push('r.process_id = ?');    params.push(process_id); }
  if (applicability){ where.push('r.applicability = ?'); params.push(applicability); }
  if (actor)        { where.push('r.actor_label = ?');   params.push(actor); }
  if (status)       { where.push("COALESCE(s.status,'not_started') = ?"); params.push(status); }
  if (owner)        { where.push('s.owner_user_id = ?'); params.push(Number(owner)); }
  if (q)            { where.push('(r.statement LIKE ? OR r.id LIKE ? OR r.name LIKE ?)');
                      params.push(`%${q}%`, `%${q}%`, `%${q}%`); }

  const sql = REQ_SELECT + (where.length ? ' WHERE ' + where.join(' AND ') : '') +
    ' ORDER BY r.process_id, r.actor_label, r.id';
  const rows = db().prepare(sql).all(...params) as any[];
  for (const r of rows) parseJsonFields(r, ['terms_json', 'affects_json', 'following_info_json', 'examples_json']);
  return c.json({ requirements: rows });
});

itemRoutes.get('/requirements/:id', (c) => {
  const id = c.req.param('id');
  const row = db().prepare(REQ_SELECT + ' WHERE r.id = ?').get(id) as any;
  if (!row) return c.json({ error: 'not found' }, 404);
  parseJsonFields(row, ['terms_json', 'affects_json', 'following_info_json', 'examples_json']);
  const raw = db().prepare(`SELECT raw_json FROM requirements WHERE id = ?`).get(id) as any;
  try { row.raw = raw?.raw_json ? JSON.parse(raw.raw_json) : null; } catch { row.raw = null; }
  const history = db().prepare(`
    SELECT a.field, a.old_value, a.new_value, a.changed_at, u.name AS user_name
    FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
    WHERE a.item_id = ? AND a.item_type = 'requirement'
    ORDER BY a.changed_at DESC LIMIT 50
  `).all(id);
  return c.json({ requirement: row, history });
});

// ---- Indicators ----

itemRoutes.get('/indicators', (c) => {
  const domain = c.req.query('domain');
  const status = c.req.query('status');
  const owner = c.req.query('owner');
  const q = c.req.query('q');

  const where: string[] = [];
  const params: any[] = [];
  if (domain) { where.push('i.domain_id = ?'); params.push(domain); }
  if (status) { where.push("COALESCE(s.status,'not_started') = ?"); params.push(status); }
  if (owner)  { where.push('s.owner_user_id = ?'); params.push(Number(owner)); }
  if (q)      { where.push('(i.statement LIKE ? OR i.id LIKE ? OR i.name LIKE ?)');
                params.push(`%${q}%`, `%${q}%`, `%${q}%`); }

  const sql = IND_SELECT + (where.length ? ' WHERE ' + where.join(' AND ') : '') +
    ' ORDER BY i.domain_id, i.id';
  const rows = db().prepare(sql).all(...params) as any[];

  // attach controls
  const ctrlStmt = db().prepare(
    `SELECT control_id FROM indicator_controls WHERE indicator_id = ? ORDER BY control_id`
  );
  for (const r of rows) {
    r.controls = (ctrlStmt.all(r.id) as any[]).map((x) => x.control_id);
  }
  return c.json({ indicators: rows });
});

itemRoutes.get('/indicators/:id', (c) => {
  const id = c.req.param('id');
  const row = db().prepare(IND_SELECT + ' WHERE i.id = ?').get(id) as any;
  if (!row) return c.json({ error: 'not found' }, 404);
  row.controls = (db().prepare(
    `SELECT control_id FROM indicator_controls WHERE indicator_id = ? ORDER BY control_id`
  ).all(id) as any[]).map((x) => x.control_id);
  const raw = db().prepare(`SELECT raw_json FROM indicators WHERE id = ?`).get(id) as any;
  try { row.raw = raw?.raw_json ? JSON.parse(raw.raw_json) : null; } catch { row.raw = null; }
  const history = db().prepare(`
    SELECT a.field, a.old_value, a.new_value, a.changed_at, u.name AS user_name
    FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
    WHERE a.item_id = ? AND a.item_type = 'indicator'
    ORDER BY a.changed_at DESC LIMIT 50
  `).all(id);
  return c.json({ indicator: row, history });
});

// ---- State mutation ----

const ALLOWED_STATUS = new Set(['not_started','in_progress','met','not_applicable','blocked']);
const ALLOWED_TYPES = new Set(['requirement','indicator']);

itemRoutes.patch('/items/:type/:id', async (c) => {
  const type = c.req.param('type');
  const id = c.req.param('id');
  if (!ALLOWED_TYPES.has(type)) return c.json({ error: 'invalid type' }, 400);

  // Verify the item exists
  const exists = type === 'requirement'
    ? db().prepare(`SELECT id FROM requirements WHERE id = ?`).get(id)
    : db().prepare(`SELECT id FROM indicators WHERE id = ?`).get(id);
  if (!exists) return c.json({ error: 'item not found' }, 404);

  const body = await c.req.json<{
    status?: string;
    owner_user_id?: number | null;
    owner_text?: string | null;
    notes?: string | null;
    evidence_url?: string | null;
    last_reviewed?: string | null;
  }>();

  if (body.status !== undefined && !ALLOWED_STATUS.has(body.status)) {
    return c.json({ error: 'invalid status' }, 400);
  }

  const user = c.get('user');

  // Load existing state for audit-log diffing
  const existing = db().prepare(
    `SELECT * FROM item_state WHERE item_id = ? AND item_type = ?`
  ).get(id, type) as any | undefined;

  const merged = {
    status:        body.status        ?? existing?.status        ?? 'not_started',
    owner_user_id: body.owner_user_id === undefined ? (existing?.owner_user_id ?? null) : body.owner_user_id,
    owner_text:    body.owner_text    === undefined ? (existing?.owner_text    ?? null) : body.owner_text,
    notes:         body.notes         === undefined ? (existing?.notes         ?? null) : body.notes,
    evidence_url:  body.evidence_url  === undefined ? (existing?.evidence_url  ?? null) : body.evidence_url,
    last_reviewed: body.last_reviewed === undefined ? (existing?.last_reviewed ?? null) : body.last_reviewed,
  };

  const fields: Array<keyof typeof merged> = ['status','owner_user_id','owner_text','notes','evidence_url','last_reviewed'];
  const tx = db().transaction(() => {
    db().prepare(`
      INSERT INTO item_state (item_id, item_type, status, owner_user_id, owner_text, notes, evidence_url, last_reviewed, updated_by, updated_at)
      VALUES (@item_id, @item_type, @status, @owner_user_id, @owner_text, @notes, @evidence_url, @last_reviewed, @updated_by, datetime('now'))
      ON CONFLICT(item_id, item_type) DO UPDATE SET
        status = excluded.status,
        owner_user_id = excluded.owner_user_id,
        owner_text = excluded.owner_text,
        notes = excluded.notes,
        evidence_url = excluded.evidence_url,
        last_reviewed = excluded.last_reviewed,
        updated_by = excluded.updated_by,
        updated_at = datetime('now')
    `).run({
      item_id: id, item_type: type, ...merged, updated_by: user.id,
    });

    const audit = db().prepare(`
      INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (const f of fields) {
      const oldV = existing ? existing[f] : null;
      const newV = merged[f];
      if ((oldV ?? null) !== (newV ?? null)) {
        audit.run(user.id, id, type, f, oldV == null ? null : String(oldV), newV == null ? null : String(newV));
      }
    }
  });
  tx();

  return c.json({ ok: true, state: merged });
});

// ---- Users (for owner picker) ----

itemRoutes.get('/users', (c) => {
  const rows = db().prepare(
    `SELECT id, email, name, role FROM users ORDER BY name`
  ).all();
  return c.json({ users: rows });
});
