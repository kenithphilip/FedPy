/**
 * API-token management routes (admin-only).
 * Tokens are shown to the admin ONCE at creation time and then SHA-256 hashed at rest.
 */
import { Hono } from 'hono';
import { db } from '../db.ts';
import { createApiToken, requireAdmin } from '../auth.ts';
import { rateLimit, RL } from '../rate-limit.ts';

export const tokenRoutes = new Hono();
tokenRoutes.use('*', requireAdmin);

tokenRoutes.get('/tokens', (c) => {
  const rows = db().prepare(`
    SELECT t.id, t.name, t.scope, t.created_at, t.last_used, t.expires_at, t.revoked_at,
           u.name AS created_by_name
    FROM api_tokens t
    LEFT JOIN users u ON u.id = t.created_by
    ORDER BY t.created_at DESC
  `).all();
  return c.json({ tokens: rows });
});

tokenRoutes.post('/tokens', rateLimit(RL.TOKEN_CREATE), async (c) => {
  let body: { name?: string; scope?: string; ttl_days?: number };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  if (!body.name || body.name.length < 3) return c.json({ error: 'name required (>= 3 chars)' }, 400);
  if (body.name.length > 200) return c.json({ error: 'name too long (max 200 chars)' }, 400);
  if (body.ttl_days != null && (!Number.isInteger(body.ttl_days) || body.ttl_days <= 0 || body.ttl_days > 3650)) {
    return c.json({ error: 'ttl_days must be a positive integer (<= 3650)' }, 400);
  }
  const scope = body.scope ?? 'patch:indicators';
  if (!['patch:indicators', 'patch:all', 'read:all'].includes(scope)) {
    return c.json({ error: 'invalid scope' }, 400);
  }
  const user = c.get('user');
  const { id, rawToken } = createApiToken(body.name, scope as any, user.id, body.ttl_days);
  // Raw token returned ONCE here; never stored.
  return c.json({ id, name: body.name, scope, token: rawToken, warning: 'This token will not be shown again. Copy it now.' });
});

tokenRoutes.post('/tokens/:id/revoke', (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isInteger(id)) return c.json({ error: 'invalid token id' }, 400);
  const r = db().prepare(`UPDATE api_tokens SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL`).run(id);
  if (r.changes === 0) return c.json({ error: 'not found or already revoked' }, 404);
  return c.json({ ok: true });
});
