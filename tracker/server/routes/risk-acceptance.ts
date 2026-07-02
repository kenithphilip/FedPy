/**
 * LOOP-B.B3 — Risk-acceptance workflow routes (NIST CA-5 / RA-7 / FedRAMP
 * Deviation Request + Risk Adjustment Request).
 *
 *   POST   /api/risk-acceptances            — create a pending acceptance (iso/admin)
 *   GET    /api/risk-acceptances            — list (filter + paginate); returns public_key
 *   GET    /api/risk-acceptances/:uuid      — detail + signed-audit history
 *   GET    /api/risk-acceptances/:uuid/verify — re-verify the record's signature
 *   POST   /api/risk-acceptances/:uuid/approve — AO approval (ao/admin) + 2nd signature
 *   POST   /api/risk-acceptances/:uuid/revoke  — revoke (iso/ao/admin)
 *   POST   /api/risk-acceptances/:uuid/expire  — manual expire (admin only)
 *
 * REO notes:
 *   - business_justification is verbatim operator input (min 100 chars, server-enforced);
 *     no default text is ever inserted.
 *   - The acceptance signature (Ed25519 over canonical JSON) is written at create time;
 *     a second approval_signature is written at approval time. The system never
 *     auto-approves — approval requires the ao/admin permission and a live user.
 *   - Only status='approved' AND expiration_date>now() rows propagate to OSCAL
 *     risk.status='deviation-approved' (enforced on the cloud-evidence reader side).
 */
import { Hono } from 'hono';
import { randomUUID } from 'node:crypto';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';
import { requirePermission } from '../rbac.ts';
import {
  acceptancePayload,
  approvalPayload,
  getPublicKeyPem,
  signPayload,
  verifyPayload,
} from '../risk-acceptance-sign.ts';

export const riskAcceptanceRoutes = new Hono();
riskAcceptanceRoutes.use('*', requireAuth);

const ACCEPTANCE_TYPES = new Set(['deviation-request', 'risk-adjustment', 'false-positive', 'operational-requirement']);
const MIN_JUSTIFICATION = 100;
const MIN_REVOCATION_REASON = 30;
const MIN_DAYS = 7;
const MAX_DAYS = 365;
const DAY_MS = 86_400_000;

function nowIso(): string {
  return new Date().toISOString();
}

interface RiskAcceptanceRow {
  id: number;
  uuid: string;
  finding_uuid: string;
  poam_item_uuid: string;
  ksi_id: string;
  rule: string;
  provider: string;
  accepted_by_user_id: number;
  accepted_at: string;
  expiration_date: string;
  business_justification: string;
  acceptance_type: string;
  status: 'pending' | 'approved' | 'expired' | 'revoked';
  approved_by_user_id: number | null;
  approved_at: string | null;
  signature: string;
  signing_key_id: string;
  approval_signature: string | null;
  approval_signing_key_id: string | null;
  revoked_at: string | null;
  revoked_by_user_id: number | null;
  revocation_reason: string | null;
}

function compensatingUuids(acceptanceId: number): string[] {
  return (db().prepare(
    `SELECT compensating_control_uuid AS u FROM risk_acceptance_compensating_links WHERE acceptance_id = ? ORDER BY compensating_control_uuid`,
  ).all(acceptanceId) as Array<{ u: string }>).map((r) => r.u);
}

/** Shape returned over the wire — includes the joined compensating-control uuids. */
function serialize(row: RiskAcceptanceRow) {
  return { ...row, compensating_control_uuids: compensatingUuids(row.id) };
}

function findByUuid(uuid: string): RiskAcceptanceRow | undefined {
  return db().prepare(`SELECT * FROM risk_acceptances WHERE uuid = ?`).get(uuid) as RiskAcceptanceRow | undefined;
}

function writeAudit(userId: number | null, uuid: string, field: string, oldValue: string | null, newValue: string | null): void {
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'risk_acceptance', ?, ?, ?)`,
  ).run(userId, `acceptance:${uuid}`, field, oldValue, newValue);
}

// ─── Create ───────────────────────────────────────────────────────────────────
riskAcceptanceRoutes.post('/', requirePermission('create:risk_acceptance'), async (c) => {
  const user = c.get('user') as { id: number };
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'invalid_json', message: 'Request body must be valid JSON.' }, 400);
  }

  const findingUuid = typeof body.finding_uuid === 'string' ? body.finding_uuid.trim() : '';
  const poamItemUuid = typeof body.poam_item_uuid === 'string' ? body.poam_item_uuid.trim() : '';
  const ksiId = typeof body.ksi_id === 'string' ? body.ksi_id.trim() : '';
  const rule = typeof body.rule === 'string' ? body.rule.trim() : '';
  const provider = typeof body.provider === 'string' ? body.provider.trim() : '';
  const expirationDate = typeof body.expiration_date === 'string' ? body.expiration_date.trim() : '';
  const justification = typeof body.business_justification === 'string' ? body.business_justification : '';
  const acceptanceType = typeof body.acceptance_type === 'string' ? body.acceptance_type : '';
  const ccUuids = Array.isArray(body.compensating_control_uuids)
    ? (body.compensating_control_uuids.filter((x): x is string => typeof x === 'string' && x.trim().length > 0)).map((s) => s.trim())
    : [];

  if (!findingUuid || !poamItemUuid || !ksiId || !rule || !provider) {
    return c.json({ error: 'missing_fields', message: 'finding_uuid, poam_item_uuid, ksi_id, rule, and provider are required.' }, 400);
  }
  if (!ACCEPTANCE_TYPES.has(acceptanceType)) {
    return c.json({ error: 'invalid_acceptance_type', message: `acceptance_type must be one of ${[...ACCEPTANCE_TYPES].join(', ')}.` }, 400);
  }
  if (justification.length < MIN_JUSTIFICATION) {
    return c.json({ error: 'justification_too_short', message: `business_justification must be at least ${MIN_JUSTIFICATION} characters (got ${justification.length}).` }, 400);
  }
  const expMs = Date.parse(expirationDate);
  if (!Number.isFinite(expMs)) {
    return c.json({ error: 'invalid_expiration_date', message: 'expiration_date must be an ISO datetime.' }, 400);
  }
  const now = Date.now();
  if (expMs < now + MIN_DAYS * DAY_MS) {
    return c.json({ error: 'expiration_too_soon', message: `expiration_date must be at least ${MIN_DAYS} days from now.` }, 400);
  }
  if (expMs > now + MAX_DAYS * DAY_MS) {
    return c.json({ error: 'expiration_too_far', message: `expiration_date must be within ${MAX_DAYS} days (FedRAMP annual review).` }, 400);
  }
  if (acceptanceType === 'deviation-request' && ccUuids.length === 0) {
    return c.json({ error: 'compensating_control_required', message: 'A deviation-request requires at least one compensating_control_uuid.' }, 400);
  }

  const uuid = randomUUID();
  const acceptedAt = nowIso();
  const { signature, signing_key_id } = signPayload(acceptancePayload({
    finding_uuid: findingUuid,
    accepted_by_user_id: user.id,
    accepted_at: acceptedAt,
    expiration_date: expirationDate,
    business_justification: justification,
    acceptance_type: acceptanceType,
    compensating_control_uuids: ccUuids,
  }));

  const insert = db().transaction(() => {
    const info = db().prepare(
      `INSERT INTO risk_acceptances
         (uuid, finding_uuid, poam_item_uuid, ksi_id, rule, provider, accepted_by_user_id, accepted_at,
          expiration_date, business_justification, acceptance_type, status, signature, signing_key_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
    ).run(uuid, findingUuid, poamItemUuid, ksiId, rule, provider, user.id, acceptedAt,
          expirationDate, justification, acceptanceType, signature, signing_key_id);
    const acceptanceId = Number(info.lastInsertRowid);
    for (const cc of ccUuids) {
      db().prepare(
        `INSERT OR IGNORE INTO risk_acceptance_compensating_links (acceptance_id, compensating_control_uuid) VALUES (?, ?)`,
      ).run(acceptanceId, cc);
    }
    return acceptanceId;
  });
  insert();
  writeAudit(user.id, uuid, 'created', null, `pending:${acceptanceType}`);

  const row = findByUuid(uuid)!;
  return c.json({ acceptance: serialize(row) }, 201);
});

// ─── List ─────────────────────────────────────────────────────────────────────
riskAcceptanceRoutes.get('/', requirePermission('read:risk_acceptance'), (c) => {
  const status = c.req.query('status');
  const ksiId = c.req.query('ksi_id');
  const expiringBefore = c.req.query('expiring_before');
  const limit = Math.min(Math.max(Number(c.req.query('limit') ?? 50) || 50, 1), 500);
  const offset = Math.max(Number(c.req.query('offset') ?? 0) || 0, 0);

  const where: string[] = [];
  const params: unknown[] = [];
  if (status) { where.push('status = ?'); params.push(status); }
  if (ksiId) { where.push('ksi_id = ?'); params.push(ksiId); }
  if (expiringBefore) { where.push('expiration_date < ?'); params.push(expiringBefore); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const total = (db().prepare(`SELECT COUNT(*) AS c FROM risk_acceptances ${whereSql}`).get(...params) as { c: number }).c;
  const rows = db().prepare(
    `SELECT * FROM risk_acceptances ${whereSql} ORDER BY accepted_at DESC, id DESC LIMIT ? OFFSET ?`,
  ).all(...params, limit, offset) as RiskAcceptanceRow[];

  return c.json({
    items: rows.map(serialize),
    public_key: getPublicKeyPem(),
    total,
    limit,
    offset,
  });
});

// ─── Detail + verify ────────────────────────────────────────────────────────
riskAcceptanceRoutes.get('/:uuid', requirePermission('read:risk_acceptance'), (c) => {
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const audit = db().prepare(
    `SELECT user_id, field, old_value, new_value, changed_at FROM audit_log
     WHERE item_type = 'risk_acceptance' AND item_id = ? ORDER BY id`,
  ).all(`acceptance:${row.uuid}`);
  return c.json({ acceptance: serialize(row), audit });
});

riskAcceptanceRoutes.get('/:uuid/verify', requirePermission('read:risk_acceptance'), (c) => {
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  const payload = acceptancePayload({
    finding_uuid: row.finding_uuid,
    accepted_by_user_id: row.accepted_by_user_id,
    accepted_at: row.accepted_at,
    expiration_date: row.expiration_date,
    business_justification: row.business_justification,
    acceptance_type: row.acceptance_type,
    compensating_control_uuids: compensatingUuids(row.id),
  });
  const valid = verifyPayload(payload, row.signature, getPublicKeyPem());
  let approvalValid: boolean | null = null;
  if (row.status === 'approved' && row.approval_signature && row.approved_by_user_id != null && row.approved_at) {
    approvalValid = verifyPayload(approvalPayload(row.uuid, row.approved_by_user_id, row.approved_at), row.approval_signature, getPublicKeyPem());
  }
  return c.json({ valid, approval_valid: approvalValid, signing_key_id: row.signing_key_id });
});

// ─── Approve ──────────────────────────────────────────────────────────────────
riskAcceptanceRoutes.post('/:uuid/approve', requirePermission('approve:risk_acceptance'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status !== 'pending') {
    return c.json({ error: 'not_pending', message: `Only pending acceptances can be approved (current status: ${row.status}).` }, 409);
  }
  const approvedAt = nowIso();
  const { signature, signing_key_id } = signPayload(approvalPayload(row.uuid, user.id, approvedAt));
  db().prepare(
    `UPDATE risk_acceptances
       SET status = 'approved', approved_by_user_id = ?, approved_at = ?, approval_signature = ?, approval_signing_key_id = ?
     WHERE uuid = ? AND status = 'pending'`,
  ).run(user.id, approvedAt, signature, signing_key_id, row.uuid);
  writeAudit(user.id, row.uuid, 'approved', 'pending', 'approved');
  return c.json({ acceptance: serialize(findByUuid(row.uuid)!) });
});

// ─── Revoke ───────────────────────────────────────────────────────────────────
riskAcceptanceRoutes.post('/:uuid/revoke', requirePermission('revoke:risk_acceptance'), async (c) => {
  const user = c.get('user') as { id: number };
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status === 'revoked' || row.status === 'expired') {
    return c.json({ error: 'not_active', message: `Cannot revoke an acceptance in status ${row.status}.` }, 409);
  }
  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'invalid_json' }, 400);
  }
  const reason = typeof body.revocation_reason === 'string' ? body.revocation_reason.trim() : '';
  if (reason.length < MIN_REVOCATION_REASON) {
    return c.json({ error: 'reason_too_short', message: `revocation_reason must be at least ${MIN_REVOCATION_REASON} characters.` }, 400);
  }
  db().prepare(
    `UPDATE risk_acceptances SET status = 'revoked', revoked_at = ?, revoked_by_user_id = ?, revocation_reason = ? WHERE uuid = ?`,
  ).run(nowIso(), user.id, reason, row.uuid);
  writeAudit(user.id, row.uuid, 'revoked', row.status, 'revoked');
  return c.json({ acceptance: serialize(findByUuid(row.uuid)!) });
});

// ─── Manual expire (admin) ──────────────────────────────────────────────────
riskAcceptanceRoutes.post('/:uuid/expire', async (c) => {
  const user = c.get('user') as { id: number; role?: string };
  if (user.role !== 'admin') {
    return c.json({ error: 'forbidden', message: 'Manual expiry is admin-only; approved acceptances expire automatically via the enforcer.' }, 403);
  }
  const row = findByUuid(c.req.param('uuid'));
  if (!row) return c.json({ error: 'not_found' }, 404);
  if (row.status !== 'approved' && row.status !== 'pending') {
    return c.json({ error: 'not_active', message: `Cannot expire an acceptance in status ${row.status}.` }, 409);
  }
  db().prepare(`UPDATE risk_acceptances SET status = 'expired' WHERE uuid = ?`).run(row.uuid);
  writeAudit(user.id, row.uuid, 'expired', row.status, 'expired');
  return c.json({ acceptance: serialize(findByUuid(row.uuid)!) });
});
