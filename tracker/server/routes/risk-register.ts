/**
 * LOOP-B.B5 — Central Risk Register routes.
 *
 * Two routers:
 *   organisationalRisksRoutes  (mounted at /api/organisational-risks)
 *     POST   /                       — create an organisational risk (iso/ao/admin)
 *     GET    /                       — list (filter status + category; paginate)
 *     GET    /:uuid                  — detail (+ audit)
 *     PUT    /:uuid                  — edit an OPEN risk (iso/ao/admin)
 *     POST   /:uuid/close            — close out a risk (iso/ao/admin)
 *
 *   riskRegisterRoutes         (mounted at /api/risk-register)
 *     GET    /                       — aggregated register (organisational + approved
 *                                       acceptances), the tracker-resident view
 *     GET    /export.xlsx            — the same rows streamed as an .xlsx
 *
 * REO notes:
 *   - title / description / likelihood / impact / treatment / review_date are
 *     verbatim operator input; the server inserts no default risk content.
 *   - inherent_risk is computed server-side from the NIST SP 800-30 Rev 1 Table
 *     I-2 matrix (likelihood × impact) so it is never operator-fudged (Q5);
 *     residual_risk is operator-set within the same enum.
 *   - Every nist_control_ids entry validates against the committed NIST 800-53
 *     Rev 5 catalog; every compensating_control_uuids entry must exist. An invalid
 *     value returns 400 naming the offender (no silent drop).
 *   - review_date must be at least 30 days in the future (forces forward planning).
 *   - The finding-sourced RA-3 entries live in the collector's signed
 *     out/risk-register.json; this endpoint returns the tracker-resident subset
 *     (organisational + acceptance) for UI visibility (LOOP-B-RISKS B.B5-13).
 */
import { Hono } from 'hono';
import { randomUUID } from 'node:crypto';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';
import { requirePermission } from '../rbac.ts';
import { isValidControlId, catalogVersion } from '../nist-catalog.ts';
import { renderRiskRegisterXlsx, type RegisterRow, type RiskBandLike } from '../risk-register-xlsx.ts';

const MIN_TITLE = 5;
const MAX_TITLE = 200;
const MIN_DESCRIPTION = 100;
const MIN_CLOSURE_REASON = 20;
const MIN_REVIEW_DAYS = 30;

const CATEGORIES = ['third-party', 'supply-chain', 'environmental', 'contractual', 'operational', 'organisational', 'other'] as const;
const BANDS = ['very-low', 'low', 'moderate', 'high', 'very-high'] as const;
const TREATMENTS = ['accept', 'mitigate', 'transfer', 'avoid'] as const;
type Band = typeof BANDS[number];

/** NIST SP 800-30 Rev 1 Table I-2 — inherent = combine(likelihood, impact). */
const INHERENT_MATRIX: Record<Band, Record<Band, Band>> = {
  'very-high': { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'high':      { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'high', 'very-high': 'very-high' },
  'moderate':  { 'very-low': 'very-low', 'low': 'low', 'moderate': 'moderate', 'high': 'moderate', 'very-high': 'high' },
  'low':       { 'very-low': 'very-low', 'low': 'low', 'moderate': 'low', 'high': 'low', 'very-high': 'moderate' },
  'very-low':  { 'very-low': 'very-low', 'low': 'very-low', 'moderate': 'very-low', 'high': 'low', 'very-high': 'low' },
};
export function combineInherent(likelihood: Band, impact: Band): Band {
  return INHERENT_MATRIX[likelihood][impact];
}

function nowIso(): string { return new Date().toISOString(); }

interface OrgRiskRow {
  id: number; uuid: string; title: string; description: string; category: string;
  likelihood: string; impact: string; inherent_risk: string; residual_risk: string; treatment: string;
  owner_user_id: number; review_date: string; nist_control_ids: string | null; compensating_control_uuids: string | null;
  status: 'open' | 'closed'; closed_at: string | null; closed_by_user_id: number | null; closure_reason: string | null;
  created_at: string; updated_at: string;
}

function parseJsonArray(text: string | null): string[] {
  if (!text) return [];
  try { const p = JSON.parse(text); return Array.isArray(p) ? p as string[] : []; } catch { return []; }
}

function ownerLabel(userId: number): string {
  const row = db().prepare(`SELECT name FROM users WHERE id = ?`).get(userId) as { name?: string } | undefined;
  return row?.name ?? `user:${userId}`;
}

function serialize(row: OrgRiskRow) {
  return {
    ...row,
    nist_control_ids: parseJsonArray(row.nist_control_ids),
    compensating_control_uuids: parseJsonArray(row.compensating_control_uuids),
    owner: ownerLabel(row.owner_user_id),
  };
}

function findByUuid(uuid: string): OrgRiskRow | undefined {
  return db().prepare(`SELECT * FROM organisational_risks WHERE uuid = ?`).get(uuid) as OrgRiskRow | undefined;
}

function writeAudit(userId: number | null, uuid: string, field: string, oldValue: string | null, newValue: string | null): void {
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'organisational_risk', ?, ?, ?)`,
  ).run(userId, `organisational-risk:${uuid}`, field, oldValue, newValue);
}

type ValidationError = { error: string; message: string; field?: string; value?: string };
interface CleanBody {
  title: string; description: string; category: string;
  likelihood: Band; impact: Band; inherent: Band; residual: Band; treatment: string;
  ownerUserId: number; reviewDate: string; nistIds: string[]; ccUuids: string[];
}

function validateBody(body: Record<string, unknown>, defaultOwnerId: number, now = new Date()):
  | { ok: false; err: ValidationError }
  | { ok: true; v: CleanBody } {
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  const description = typeof body.description === 'string' ? body.description : '';
  const category = typeof body.category === 'string' ? body.category : '';
  const likelihood = typeof body.likelihood === 'string' ? body.likelihood : '';
  const impact = typeof body.impact === 'string' ? body.impact : '';
  const residual = typeof body.residual_risk === 'string' ? body.residual_risk : '';
  const treatment = typeof body.treatment === 'string' ? body.treatment : '';
  const reviewDate = typeof body.review_date === 'string' ? body.review_date.trim() : '';
  const ownerUserId = typeof body.owner_user_id === 'number' ? body.owner_user_id : defaultOwnerId;
  const nistIds = Array.isArray(body.nist_control_ids)
    ? body.nist_control_ids.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).map((s) => s.trim())
    : [];
  const ccUuids = Array.isArray(body.compensating_control_uuids)
    ? body.compensating_control_uuids.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).map((s) => s.trim())
    : [];

  if (title.length < MIN_TITLE || title.length > MAX_TITLE) {
    return { ok: false, err: { error: 'invalid_title', message: `title must be ${MIN_TITLE}-${MAX_TITLE} characters (got ${title.length}).`, field: 'title' } };
  }
  if (description.length < MIN_DESCRIPTION) {
    return { ok: false, err: { error: 'description_too_short', message: `description must be at least ${MIN_DESCRIPTION} characters (got ${description.length}).`, field: 'description' } };
  }
  if (!(CATEGORIES as readonly string[]).includes(category)) {
    return { ok: false, err: { error: 'invalid_category', message: `category must be one of ${CATEGORIES.join(', ')}.`, field: 'category', value: category } };
  }
  if (!(BANDS as readonly string[]).includes(likelihood)) {
    return { ok: false, err: { error: 'invalid_likelihood', message: `likelihood must be a NIST 800-30 band (${BANDS.join(', ')}).`, field: 'likelihood', value: likelihood } };
  }
  if (!(BANDS as readonly string[]).includes(impact)) {
    return { ok: false, err: { error: 'invalid_impact', message: `impact must be a NIST 800-30 band (${BANDS.join(', ')}).`, field: 'impact', value: impact } };
  }
  if (!(BANDS as readonly string[]).includes(residual)) {
    return { ok: false, err: { error: 'invalid_residual_risk', message: `residual_risk must be a NIST 800-30 band (${BANDS.join(', ')}).`, field: 'residual_risk', value: residual } };
  }
  if (!(TREATMENTS as readonly string[]).includes(treatment)) {
    return { ok: false, err: { error: 'invalid_treatment', message: `treatment must be one of ${TREATMENTS.join(', ')}.`, field: 'treatment', value: treatment } };
  }
  const reviewMs = Date.parse(reviewDate);
  if (!Number.isFinite(reviewMs)) {
    return { ok: false, err: { error: 'invalid_review_date', message: 'review_date must be an ISO datetime.', field: 'review_date' } };
  }
  if (reviewMs < now.getTime() + MIN_REVIEW_DAYS * 86_400_000) {
    return { ok: false, err: { error: 'review_date_too_soon', message: `review_date must be at least ${MIN_REVIEW_DAYS} days in the future.`, field: 'review_date' } };
  }
  const ownerRow = db().prepare(`SELECT id FROM users WHERE id = ?`).get(ownerUserId) as { id?: number } | undefined;
  if (!ownerRow) {
    return { ok: false, err: { error: 'invalid_owner', message: `owner_user_id ${ownerUserId} does not exist.`, field: 'owner_user_id' } };
  }
  for (const id of nistIds) {
    if (!isValidControlId(id)) {
      return { ok: false, err: { error: 'invalid_nist_control_id', message: `"${id}" is not a NIST SP 800-53 Rev 5 control or enhancement.`, field: 'nist_control_ids', value: id } };
    }
  }
  for (const u of ccUuids) {
    const row = db().prepare(`SELECT status FROM compensating_controls WHERE uuid = ?`).get(u) as { status?: string } | undefined;
    if (!row) {
      return { ok: false, err: { error: 'unknown_compensating_control', message: `compensating_control_uuid "${u}" does not exist.`, field: 'compensating_control_uuids', value: u } };
    }
  }
  const inherent = combineInherent(likelihood as Band, impact as Band);
  return { ok: true, v: { title, description, category, likelihood: likelihood as Band, impact: impact as Band, inherent, residual: residual as Band, treatment, ownerUserId, reviewDate, nistIds, ccUuids } };
}

// ═══ Organisational-risks router ══════════════════════════════════════════════
export const organisationalRisksRoutes = new Hono();
organisationalRisksRoutes.use('*', requireAuth);

organisationalRisksRoutes.post('/', requirePermission('create:organisational_risk'), async (c) => {
  const user = c.get('user') as { id: number };
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json' }, 400); }
  const r = validateBody(body, user.id);
  if (!r.ok) return c.json(r.err, 400);
  const { v } = r;
  const uuid = randomUUID();
  const ts = nowIso();
  db().prepare(
    `INSERT INTO organisational_risks
       (uuid, title, description, category, likelihood, impact, inherent_risk, residual_risk, treatment,
        owner_user_id, review_date, nist_control_ids, compensating_control_uuids, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)`,
  ).run(uuid, v.title, v.description, v.category, v.likelihood, v.impact, v.inherent, v.residual, v.treatment,
        v.ownerUserId, v.reviewDate, v.nistIds.length ? JSON.stringify(v.nistIds) : null,
        v.ccUuids.length ? JSON.stringify(v.ccUuids) : null, ts, ts);
  writeAudit(user.id, uuid, 'created', null, `open:${v.category}:${v.inherent}`);
  return c.json({ organisational_risk: serialize(findByUuid(uuid)!), catalog_version: catalogVersion() }, 201);
});

organisationalRisksRoutes.get('/', requirePermission('read:risk_register'), (c) => {
  const status = c.req.query('status');
  const category = c.req.query('category');
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 100) || 100, 1), 500);
  const offset = Math.max(Number(c.req.query('offset') ?? 0) || 0, 0);
  const where: string[] = [];
  const params: unknown[] = [];
  if (status) { where.push('status = ?'); params.push(status); }
  if (category) { where.push('category = ?'); params.push(category); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = (db().prepare(`SELECT COUNT(*) AS c FROM organisational_risks ${whereSql}`).get(...params) as { c: number }).c;
  const rows = db().prepare(
    `SELECT * FROM organisational_risks ${whereSql} ORDER BY
       CASE inherent_risk WHEN 'very-high' THEN 5 WHEN 'high' THEN 4 WHEN 'moderate' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC,
       created_at DESC LIMIT ? OFFSET ?`,
  ).all(...params, limit, offset) as OrgRiskRow[];
  return c.json({ items: rows.map(serialize), total, limit, offset, catalog_version: catalogVersion() });
});

organisationalRisksRoutes.get('/:uuid', requirePermission('read:risk_register'), (c) => {
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const audit = db().prepare(
    `SELECT user_id, field, old_value, new_value, changed_at FROM audit_log
     WHERE item_type = 'organisational_risk' AND item_id = ? ORDER BY id`,
  ).all(`organisational-risk:${row.uuid}`);
  return c.json({ organisational_risk: serialize(row), audit });
});

organisationalRisksRoutes.put('/:uuid', requirePermission('create:organisational_risk'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status !== 'open') {
    return c.json({ error: 'not_open', message: `Only open risks can be edited (current status: ${row.status}).` }, 409);
  }
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json' }, 400); }
  const r = validateBody(body, row.owner_user_id);
  if (!r.ok) return c.json(r.err, 400);
  const { v } = r;
  const ts = nowIso();
  db().prepare(
    `UPDATE organisational_risks
       SET title = ?, description = ?, category = ?, likelihood = ?, impact = ?, inherent_risk = ?,
           residual_risk = ?, treatment = ?, owner_user_id = ?, review_date = ?,
           nist_control_ids = ?, compensating_control_uuids = ?, updated_at = ?
     WHERE uuid = ? AND status = 'open'`,
  ).run(v.title, v.description, v.category, v.likelihood, v.impact, v.inherent, v.residual, v.treatment,
        v.ownerUserId, v.reviewDate, v.nistIds.length ? JSON.stringify(v.nistIds) : null,
        v.ccUuids.length ? JSON.stringify(v.ccUuids) : null, ts, row.uuid);
  writeAudit(user.id, row.uuid, 'updated', row.inherent_risk, v.inherent);
  return c.json({ organisational_risk: serialize(findByUuid(row.uuid)!) });
});

organisationalRisksRoutes.post('/:uuid/close', requirePermission('close:organisational_risk'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status === 'closed') {
    return c.json({ error: 'already_closed', message: 'This risk is already closed.' }, 409);
  }
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json' }, 400); }
  const reason = typeof body.closure_reason === 'string' ? body.closure_reason.trim() : '';
  if (reason.length < MIN_CLOSURE_REASON) {
    return c.json({ error: 'reason_too_short', message: `closure_reason must be at least ${MIN_CLOSURE_REASON} characters.` }, 400);
  }
  const ts = nowIso();
  db().prepare(
    `UPDATE organisational_risks SET status = 'closed', closed_at = ?, closed_by_user_id = ?, closure_reason = ?, updated_at = ? WHERE uuid = ?`,
  ).run(ts, user.id, reason, ts, row.uuid);
  writeAudit(user.id, row.uuid, 'closed', 'open', 'closed');
  return c.json({ organisational_risk: serialize(findByUuid(row.uuid)!) });
});

// ═══ Aggregated risk-register router ══════════════════════════════════════════
export const riskRegisterRoutes = new Hono();
riskRegisterRoutes.use('*', requireAuth);

/**
 * Build the tracker-resident register rows: organisational risks (verbatim bands)
 * + approved, unexpired risk acceptances (treatment=accept). Finding-sourced RA-3
 * entries come from the collector's out/risk-register.json (poam.json is not
 * tracker-resident); this endpoint is the UI-facing subset (B.B5-13).
 */
export function buildTrackerRegisterRows(now = new Date()): RegisterRow[] {
  const rows: RegisterRow[] = [];
  const orgs = db().prepare(
    `SELECT * FROM organisational_risks ORDER BY
       CASE inherent_risk WHEN 'very-high' THEN 5 WHEN 'high' THEN 4 WHEN 'moderate' THEN 3 WHEN 'low' THEN 2 ELSE 1 END DESC`,
  ).all() as OrgRiskRow[];
  for (const o of orgs) {
    rows.push({
      uuid: o.uuid, source: 'organisational', title: o.title, category: o.category,
      likelihood: o.likelihood as RiskBandLike, impact: o.impact as RiskBandLike,
      inherent_risk: o.inherent_risk as RiskBandLike, residual_risk: o.residual_risk as RiskBandLike,
      treatment: o.treatment, owner: ownerLabel(o.owner_user_id), review_date: o.review_date, status: o.status,
      nist_control_ids: parseJsonArray(o.nist_control_ids), compensating_control_uuids: parseJsonArray(o.compensating_control_uuids),
      description: o.description,
    });
  }
  const nowIsoStr = now.toISOString();
  const accs = db().prepare(
    `SELECT uuid, poam_item_uuid, ksi_id, rule, business_justification, acceptance_type, expiration_date
       FROM risk_acceptances WHERE status = 'approved' AND expiration_date > ? ORDER BY expiration_date`,
  ).all(nowIsoStr) as Array<{ uuid: string; poam_item_uuid: string; ksi_id: string; rule: string; business_justification: string; acceptance_type: string; expiration_date: string }>;
  for (const a of accs) {
    rows.push({
      uuid: a.uuid, source: 'acceptance', title: `Accepted risk: ${a.ksi_id} / ${a.rule}`, category: a.acceptance_type,
      likelihood: 'REQUIRES-OPERATOR-INPUT', impact: 'REQUIRES-OPERATOR-INPUT',
      inherent_risk: 'REQUIRES-OPERATOR-INPUT', residual_risk: 'REQUIRES-OPERATOR-INPUT',
      treatment: 'accept', owner: 'AO', review_date: a.expiration_date, status: 'open',
      acceptance_uuid: a.uuid, poam_item_uuid: a.poam_item_uuid, description: a.business_justification,
    });
  }
  return rows;
}

riskRegisterRoutes.get('/', requirePermission('read:risk_register'), (c) => {
  const rows = buildTrackerRegisterRows();
  const by_source: Record<string, number> = { finding: 0, acceptance: 0, organisational: 0 };
  let high_inherent = 0;
  for (const r of rows) {
    by_source[r.source] = (by_source[r.source] ?? 0) + 1;
    if (r.inherent_risk === 'high' || r.inherent_risk === 'very-high') high_inherent++;
  }
  return c.json({ entries: rows, summary: { entries_total: rows.length, by_source, high_inherent_count: high_inherent } });
});

riskRegisterRoutes.get('/export.xlsx', requirePermission('read:risk_register'), (c) => {
  const buf = renderRiskRegisterXlsx(buildTrackerRegisterRows());
  // Copy into a fresh ArrayBuffer-backed Uint8Array (Hono's body type rejects a
  // possibly-SharedArrayBuffer-backed Node Buffer).
  const bytes = new Uint8Array(buf.byteLength);
  bytes.set(buf);
  return c.body(bytes, 200, {
    'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'content-disposition': 'attachment; filename="risk-register.xlsx"',
  });
});
