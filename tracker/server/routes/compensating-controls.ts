/**
 * LOOP-B.B4 — Compensating-controls registry routes (NIST 800-53A §2.4 /
 * CA-5(1) automation / CA-2(1) assessor evidence / PL-2 SSP narrative id).
 *
 *   POST   /api/compensating-controls              — create a draft (iso/admin)
 *   GET    /api/compensating-controls              — list (filter status + nist id; paginate); returns public_key
 *   GET    /api/compensating-controls/uuid-exists  — cross-check a set of uuids (B.B3 create-form + reader)
 *   GET    /api/compensating-controls/:uuid        — detail + linked acceptances + audit
 *   GET    /api/compensating-controls/:uuid/verify — re-verify the record + activation signatures
 *   PUT    /api/compensating-controls/:uuid        — edit a DRAFT (re-signs); active/retired are immutable
 *   POST   /api/compensating-controls/:uuid/activate — AO sign-off (ao/admin): draft → active + 2nd signature
 *   POST   /api/compensating-controls/:uuid/retire   — retire an active control (iso/ao/admin)
 *
 * REO notes:
 *   - title / description / nist_control_ids / evidence_url are verbatim operator
 *     input; the server inserts no default text.
 *   - Every nist_control_ids entry validates against the committed NIST 800-53 Rev 5
 *     catalog; an invalid id returns 400 naming the offending value (no silent drop).
 *   - The record signature (Ed25519 over canonical JSON) is written at create time;
 *     a second activation_signature is written at AO sign-off. The system never
 *     auto-activates — activation requires the activate permission and a live AO.
 *   - Only status='active' AND (expiration_date IS NULL OR > now) rows propagate to
 *     OSCAL risk.remediations[] (enforced again on the cloud-evidence reader side).
 */
import { Hono } from 'hono';
import { randomUUID } from 'node:crypto';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';
import { requirePermission } from '../rbac.ts';
import { isValidControlId, catalogVersion } from '../nist-catalog.ts';
import {
  activationPayload,
  compensatingControlPayload,
  getPublicKeyPem,
  signPayload,
  verifyPayload,
} from '../compensating-control-sign.ts';

export const compensatingControlRoutes = new Hono();
compensatingControlRoutes.use('*', requireAuth);

const MIN_TITLE = 5;
const MAX_TITLE = 200;
const MIN_DESCRIPTION = 200;
const MIN_RETIREMENT_REASON = 30;

function nowIso(): string {
  return new Date().toISOString();
}

interface CompensatingControlRow {
  id: number;
  uuid: string;
  title: string;
  description: string;
  nist_control_ids: string;              // JSON array text in the DB
  implemented_by_user_id: number;
  implemented_at: string;
  signed_off_by_user_id: number | null;
  signed_off_at: string | null;
  expiration_date: string | null;
  evidence_url: string | null;
  evidence_sha256: string | null;
  status: 'draft' | 'active' | 'retired';
  signature: string;
  signing_key_id: string;
  activation_signature: string | null;
  activation_signing_key_id: string | null;
  retired_at: string | null;
  retired_by_user_id: number | null;
  retirement_reason: string | null;
  created_at: string;
  updated_at: string;
}

/** Shape returned over the wire — nist_control_ids parsed from its JSON text column. */
function serialize(row: CompensatingControlRow) {
  let nistIds: string[] = [];
  try { const p = JSON.parse(row.nist_control_ids); if (Array.isArray(p)) nistIds = p as string[]; } catch { /* keep [] */ }
  return { ...row, nist_control_ids: nistIds };
}

function findByUuid(uuid: string): CompensatingControlRow | undefined {
  return db().prepare(`SELECT * FROM compensating_controls WHERE uuid = ?`).get(uuid) as CompensatingControlRow | undefined;
}

function writeAudit(userId: number | null, uuid: string, field: string, oldValue: string | null, newValue: string | null): void {
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'compensating_control', ?, ?, ?)`,
  ).run(userId, `compensating-control:${uuid}`, field, oldValue, newValue);
}

/** Acceptances (pending/approved) that reference this control — blocks retirement (B.B4-4). */
function activeLinkedAcceptances(uuid: string): Array<{ uuid: string; status: string }> {
  return db().prepare(
    `SELECT ra.uuid AS uuid, ra.status AS status
       FROM risk_acceptance_compensating_links l
       JOIN risk_acceptances ra ON ra.id = l.acceptance_id
      WHERE l.compensating_control_uuid = ? AND ra.status IN ('pending','approved')
      ORDER BY ra.uuid`,
  ).all(uuid) as Array<{ uuid: string; status: string }>;
}

/**
 * Validate + normalise a create/update body. Returns either an error tuple
 * (status + JSON body) or the cleaned fields ready to sign + persist.
 */
type ValidationError = { error: string; message: string; field?: string; value?: string };
function validateBody(body: Record<string, unknown>):
  | { ok: false; err: ValidationError }
  | { ok: true; title: string; description: string; nistIds: string[]; evidenceUrl: string | null; evidenceSha256: string | null; expirationDate: string | null } {
  const title = typeof body.title === 'string' ? body.title.trim() : '';
  const description = typeof body.description === 'string' ? body.description : '';
  const nistIdsRaw = Array.isArray(body.nist_control_ids)
    ? body.nist_control_ids.filter((x): x is string => typeof x === 'string' && x.trim().length > 0).map((s) => s.trim())
    : null;
  const evidenceUrl = typeof body.evidence_url === 'string' && body.evidence_url.trim() ? body.evidence_url.trim() : null;
  const evidenceSha256 = typeof body.evidence_sha256 === 'string' && body.evidence_sha256.trim() ? body.evidence_sha256.trim() : null;
  const expirationRaw = typeof body.expiration_date === 'string' && body.expiration_date.trim() ? body.expiration_date.trim() : null;

  if (title.length < MIN_TITLE || title.length > MAX_TITLE) {
    return { ok: false, err: { error: 'invalid_title', message: `title must be ${MIN_TITLE}-${MAX_TITLE} characters (got ${title.length}).`, field: 'title' } };
  }
  if (description.length < MIN_DESCRIPTION) {
    return { ok: false, err: { error: 'description_too_short', message: `description must be at least ${MIN_DESCRIPTION} characters (got ${description.length}).`, field: 'description' } };
  }
  if (!nistIdsRaw || nistIdsRaw.length === 0) {
    return { ok: false, err: { error: 'missing_nist_control_ids', message: 'nist_control_ids must be a non-empty array of NIST 800-53 Rev 5 control ids.', field: 'nist_control_ids' } };
  }
  for (const id of nistIdsRaw) {
    if (!isValidControlId(id)) {
      return { ok: false, err: { error: 'invalid_nist_control_id', message: `"${id}" is not a NIST SP 800-53 Rev 5 control or enhancement.`, field: 'nist_control_ids', value: id } };
    }
  }
  let expirationDate: string | null = null;
  if (expirationRaw !== null) {
    const ms = Date.parse(expirationRaw);
    if (!Number.isFinite(ms)) {
      return { ok: false, err: { error: 'invalid_expiration_date', message: 'expiration_date must be an ISO datetime.', field: 'expiration_date' } };
    }
    expirationDate = expirationRaw;
  }
  return { ok: true, title, description, nistIds: nistIdsRaw, evidenceUrl, evidenceSha256, expirationDate };
}

// ─── Create ─────────────────────────────────────────────────────────────────
compensatingControlRoutes.post('/', requirePermission('create:compensating_control'), async (c) => {
  const user = c.get('user') as { id: number };
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json', message: 'Request body must be valid JSON.' }, 400); }

  const v = validateBody(body);
  if (!v.ok) return c.json(v.err, 400);

  const uuid = randomUUID();
  const implementedAt = nowIso();
  const { signature, signing_key_id } = signPayload(compensatingControlPayload({
    title: v.title,
    description: v.description,
    nist_control_ids: v.nistIds,
    implemented_by_user_id: user.id,
    implemented_at: implementedAt,
    evidence_url: v.evidenceUrl,
    evidence_sha256: v.evidenceSha256,
  }));

  db().prepare(
    `INSERT INTO compensating_controls
       (uuid, title, description, nist_control_ids, implemented_by_user_id, implemented_at,
        expiration_date, evidence_url, evidence_sha256, status, signature, signing_key_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)`,
  ).run(uuid, v.title, v.description, JSON.stringify(v.nistIds), user.id, implementedAt,
        v.expirationDate, v.evidenceUrl, v.evidenceSha256, signature, signing_key_id, implementedAt, implementedAt);
  writeAudit(user.id, uuid, 'created', null, `draft:${v.nistIds.join(',')}`);

  return c.json({ compensating_control: serialize(findByUuid(uuid)!), catalog_version: catalogVersion() }, 201);
});

// ─── List ───────────────────────────────────────────────────────────────────
compensatingControlRoutes.get('/', requirePermission('read:compensating_control'), (c) => {
  const status = c.req.query('status');
  const nistId = c.req.query('nist_control_id');
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 50) || 50, 1), 500);
  const offset = Math.max(Number(c.req.query('offset') ?? 0) || 0, 0);

  const where: string[] = [];
  const params: unknown[] = [];
  if (status) { where.push('status = ?'); params.push(status); }
  // nist_control_ids is a JSON array text column; a LIKE on the quoted id is an
  // index-free but correct contains check (the registry is small — B.B4-5).
  if (nistId) { where.push('nist_control_ids LIKE ?'); params.push(`%${JSON.stringify(nistId).slice(1, -1)}%`); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const total = (db().prepare(`SELECT COUNT(*) AS c FROM compensating_controls ${whereSql}`).get(...params) as { c: number }).c;
  const rows = db().prepare(
    `SELECT * FROM compensating_controls ${whereSql} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
  ).all(...params, limit, offset) as CompensatingControlRow[];

  return c.json({ items: rows.map(serialize), public_key: getPublicKeyPem(), catalog_version: catalogVersion(), total, limit, offset });
});

// ─── uuid-exists cross-check (must precede /:uuid) ────────────────────────────
compensatingControlRoutes.get('/uuid-exists', requirePermission('read:compensating_control'), (c) => {
  const raw = c.req.query('uuids') ?? '';
  const uuids = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const result: Record<string, boolean> = {};
  for (const u of uuids) {
    const row = db().prepare(`SELECT status FROM compensating_controls WHERE uuid = ?`).get(u) as { status?: string } | undefined;
    // "exists" for the acceptance create-form means a usable (non-retired) control.
    result[u] = !!row && row.status !== 'retired';
  }
  return c.json({ exists: result });
});

// ─── Detail (+ linked acceptances + audit) ────────────────────────────────────
compensatingControlRoutes.get('/:uuid', requirePermission('read:compensating_control'), (c) => {
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const audit = db().prepare(
    `SELECT user_id, field, old_value, new_value, changed_at FROM audit_log
     WHERE item_type = 'compensating_control' AND item_id = ? ORDER BY id`,
  ).all(`compensating-control:${row.uuid}`);
  const linkedAcceptances = db().prepare(
    `SELECT ra.uuid AS uuid, ra.status AS status, ra.ksi_id AS ksi_id, ra.rule AS rule
       FROM risk_acceptance_compensating_links l
       JOIN risk_acceptances ra ON ra.id = l.acceptance_id
      WHERE l.compensating_control_uuid = ? ORDER BY ra.uuid`,
  ).all(row.uuid);
  return c.json({ compensating_control: serialize(row), linked_acceptances: linkedAcceptances, audit, public_key: getPublicKeyPem() });
});

// ─── Verify signatures ────────────────────────────────────────────────────────
compensatingControlRoutes.get('/:uuid/verify', requirePermission('read:compensating_control'), (c) => {
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const ser = serialize(row);
  const payload = compensatingControlPayload({
    title: row.title,
    description: row.description,
    nist_control_ids: ser.nist_control_ids,
    implemented_by_user_id: row.implemented_by_user_id,
    implemented_at: row.implemented_at,
    evidence_url: row.evidence_url,
    evidence_sha256: row.evidence_sha256,
  });
  const valid = verifyPayload(payload, row.signature, getPublicKeyPem());
  let activationValid: boolean | null = null;
  if (row.status === 'active' && row.activation_signature && row.signed_off_by_user_id != null && row.signed_off_at) {
    activationValid = verifyPayload(activationPayload(row.uuid, row.signed_off_by_user_id, row.signed_off_at), row.activation_signature, getPublicKeyPem());
  }
  return c.json({ valid, activation_valid: activationValid, signing_key_id: row.signing_key_id });
});

// ─── Update (draft only) ──────────────────────────────────────────────────────
compensatingControlRoutes.put('/:uuid', requirePermission('create:compensating_control'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status !== 'draft') {
    return c.json({ error: 'not_draft', message: `Only draft controls can be edited (current status: ${row.status}). Retire this control and create a new one.` }, 409);
  }
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json' }, 400); }
  const v = validateBody(body);
  if (!v.ok) return c.json(v.err, 400);

  const updatedAt = nowIso();
  // Re-sign: the signed payload keeps the ORIGINAL implemented_at/implementer so
  // the create-time provenance is stable; only the mutable content changes.
  const { signature, signing_key_id } = signPayload(compensatingControlPayload({
    title: v.title,
    description: v.description,
    nist_control_ids: v.nistIds,
    implemented_by_user_id: row.implemented_by_user_id,
    implemented_at: row.implemented_at,
    evidence_url: v.evidenceUrl,
    evidence_sha256: v.evidenceSha256,
  }));
  db().prepare(
    `UPDATE compensating_controls
       SET title = ?, description = ?, nist_control_ids = ?, evidence_url = ?, evidence_sha256 = ?,
           expiration_date = ?, signature = ?, signing_key_id = ?, updated_at = ?
     WHERE uuid = ? AND status = 'draft'`,
  ).run(v.title, v.description, JSON.stringify(v.nistIds), v.evidenceUrl, v.evidenceSha256,
        v.expirationDate, signature, signing_key_id, updatedAt, row.uuid);
  writeAudit(user.id, row.uuid, 'updated', 'draft', 'draft');
  return c.json({ compensating_control: serialize(findByUuid(row.uuid)!) });
});

// ─── Activate (AO sign-off; draft → active) ───────────────────────────────────
compensatingControlRoutes.post('/:uuid/activate', requirePermission('activate:compensating_control'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status !== 'draft') {
    return c.json({ error: 'not_draft', message: `Only draft controls can be activated (current status: ${row.status}).` }, 409);
  }
  const signedOffAt = nowIso();
  const { signature, signing_key_id } = signPayload(activationPayload(row.uuid, user.id, signedOffAt));
  db().prepare(
    `UPDATE compensating_controls
       SET status = 'active', signed_off_by_user_id = ?, signed_off_at = ?,
           activation_signature = ?, activation_signing_key_id = ?, updated_at = ?
     WHERE uuid = ? AND status = 'draft'`,
  ).run(user.id, signedOffAt, signature, signing_key_id, signedOffAt, row.uuid);
  writeAudit(user.id, row.uuid, 'activated', 'draft', 'active');
  return c.json({ compensating_control: serialize(findByUuid(row.uuid)!) });
});

// ─── Retire (active → retired) ────────────────────────────────────────────────
compensatingControlRoutes.post('/:uuid/retire', requirePermission('retire:compensating_control'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status === 'retired') {
    return c.json({ error: 'already_retired', message: 'This control is already retired.' }, 409);
  }
  let body: Record<string, unknown>;
  try { body = await c.req.json(); } catch { return c.json({ error: 'invalid_json' }, 400); }
  const reason = typeof body.retirement_reason === 'string' ? body.retirement_reason.trim() : '';
  if (reason.length < MIN_RETIREMENT_REASON) {
    return c.json({ error: 'reason_too_short', message: `retirement_reason must be at least ${MIN_RETIREMENT_REASON} characters.` }, 400);
  }
  // B.B4-4: a control cited by a still-active acceptance cannot be retired — the
  // acceptance would be left claiming a mitigation that no longer exists.
  const links = activeLinkedAcceptances(row.uuid);
  if (links.length > 0) {
    return c.json({
      error: 'linked_acceptances_active',
      message: `Cannot retire: ${links.length} active acceptance(s) still reference this control. Revoke them first.`,
      acceptances: links,
    }, 409);
  }
  const retiredAt = nowIso();
  db().prepare(
    `UPDATE compensating_controls SET status = 'retired', retired_at = ?, retired_by_user_id = ?, retirement_reason = ?, updated_at = ? WHERE uuid = ?`,
  ).run(retiredAt, user.id, reason, retiredAt, row.uuid);
  writeAudit(user.id, row.uuid, 'retired', row.status, 'retired');
  return c.json({ compensating_control: serialize(findByUuid(row.uuid)!) });
});
