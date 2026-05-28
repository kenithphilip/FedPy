/**
 * Admin routes: user listing + role + domain assignment management.
 *
 *   GET    /api/users                       — list all users (admin only)
 *   PATCH  /api/users/:id/role              — change a user's role
 *   GET    /api/users/:id/domains           — list a user's KSI domain assignments
 *   POST   /api/users/:id/domains           — assign a domain
 *   DELETE /api/users/:id/domains/:domain   — unassign a domain
 *
 * All routes require `manage:users` permission (admin role).
 * All mutations are recorded in audit_log via rbac.ts helpers.
 */
import { Hono } from 'hono';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';
import { requirePermission, changeRole, assignDomain, unassignDomain, listUserDomains, ROLES } from '../rbac.ts';

export const adminRoutes = new Hono();
adminRoutes.use('*', requireAuth);

adminRoutes.get('/', requirePermission('manage:users'), (c) => {
  const rows = db().prepare(`
    SELECT id, email, name, role, created_at,
           CASE WHEN totp_enrolled_at IS NOT NULL THEN 1 ELSE 0 END AS twofa_enrolled,
           require_2fa
    FROM users ORDER BY id
  `).all();
  return c.json({ users: rows });
});

adminRoutes.patch('/:id/role', requirePermission('manage:users'), async (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isFinite(id)) return c.json({ error: 'invalid user id' }, 400);
  const { role } = await c.req.json<{ role?: string }>();
  if (!role || !ROLES.includes(role as any)) {
    return c.json({ error: `role must be one of ${ROLES.join(', ')}` }, 400);
  }

  const actingUser = c.get('user') as any;

  // Refuse to leave the system without an admin. Two failure modes prevented:
  //   1. An admin demoting themselves to a non-admin role.
  //   2. An admin demoting the LAST other admin.
  if (role !== 'admin') {
    const targetRow = db().prepare(`SELECT role FROM users WHERE id = ?`).get(id) as { role?: string } | undefined;
    if (targetRow?.role === 'admin') {
      const adminCount = (db().prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'admin'`).get() as { c: number }).c;
      if (adminCount <= 1) {
        return c.json({
          error: 'last_admin',
          message: 'Cannot remove the last admin role; promote another user to admin first.',
        }, 409);
      }
      if (id === actingUser?.id) {
        return c.json({
          error: 'self_demotion_blocked',
          message: 'Admins cannot demote themselves. Ask another admin to do it.',
        }, 409);
      }
    }
  }

  try {
    changeRole(id, role as any, actingUser?.id ?? null);
    return c.json({ ok: true });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

adminRoutes.get('/:id/domains', requirePermission('manage:users'), (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isFinite(id)) return c.json({ error: 'invalid user id' }, 400);
  return c.json({ domains: listUserDomains(id) });
});

adminRoutes.post('/:id/domains', requirePermission('manage:users'), async (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isFinite(id)) return c.json({ error: 'invalid user id' }, 400);
  let domain: string | undefined;
  try {
    ({ domain } = await c.req.json<{ domain?: string }>());
  } catch {
    return c.json({ error: 'invalid JSON body' }, 400);
  }
  if (!domain || !/^[A-Za-z]{2,10}$/.test(domain)) return c.json({ error: 'domain must be 2–10 letters (e.g. IAM, MLA)' }, 400);
  assignDomain(id, domain, (c.get('user') as any).id);
  return c.json({ ok: true });
});

adminRoutes.delete('/:id/domains/:domain', requirePermission('manage:users'), (c) => {
  const id = Number(c.req.param('id'));
  if (!Number.isFinite(id)) return c.json({ error: 'invalid user id' }, 400);
  const domain = c.req.param('domain');
  unassignDomain(id, domain, (c.get('user') as any).id);
  return c.json({ ok: true });
});
