/**
 * Role-based access control.
 *
 * Roles (least → most privileged):
 *   viewer       — read-only access to all items + reports
 *   contributor  — viewer + may edit item_state for items they're assigned to
 *   ksi-owner    — contributor + may edit ANY item in their assigned domain (e.g. all KSI-IAM-*)
 *   auditor      — viewer + may access audit log + immutable evidence (read-only forever)
 *   admin        — all permissions, including user management + 2FA enforcement
 *
 * Legacy mapping:
 *   - The existing `users.role` column has values 'admin' | 'member'.
 *     We map 'admin' → 'admin' and 'member' → 'contributor' for backward
 *     compatibility. New deployments can assign granular roles.
 *
 * Permission model:
 *   - Each role implies a set of action+scope tuples ("can.read.items",
 *     "can.edit.items", "can.manage.users", etc.).
 *   - Per-KSI-domain assignments live in user_domain_assignments (added in
 *     this migration) and bind a user to a domain code like "IAM" or "MLA".
 *   - `requirePermission(action, scope)` is a Hono middleware factory that
 *     returns 403 if the current session lacks the permission.
 *
 * Audit:
 *   - Every role change and domain assignment is logged in `audit_log` via
 *     the changeRole() / assignDomain() helpers.
 */
import type { MiddlewareHandler } from 'hono';
import { db } from './db.ts';

// LOOP-B.B3 added three FedRAMP separation-of-duties roles for the risk-acceptance
// workflow: iso (Information System Owner — creates/revokes), ao (Authorizing
// Official — approves), and assessor (3PAO — read-only). Keeping them distinct
// from admin preserves the AO-approval separation of duties (an iso can create a
// deviation request but cannot approve it; only an ao or admin can).
export type Role = 'viewer' | 'contributor' | 'ksi-owner' | 'auditor' | 'iso' | 'ao' | 'assessor' | 'admin';

export const ROLES: Role[] = ['viewer', 'contributor', 'ksi-owner', 'auditor', 'iso', 'ao', 'assessor', 'admin'];

/** Bitmasks would be premature here; use explicit permissions for legibility. */
export type Permission =
  | 'read:items'
  | 'edit:items:assigned'   // edit items where I'm the owner
  | 'edit:items:domain'     // edit items in my assigned KSI domain(s)
  | 'edit:items:all'
  | 'manage:tokens'
  | 'manage:users'
  | 'read:audit_log'
  | 'manage:2fa_policy'
  // LOOP-B.B3 risk-acceptance workflow
  | 'read:risk_acceptance'
  | 'create:risk_acceptance'
  | 'approve:risk_acceptance'
  | 'revoke:risk_acceptance'
  // LOOP-B.B4 compensating-controls registry
  | 'read:compensating_control'
  | 'create:compensating_control'      // create draft + edit draft
  | 'activate:compensating_control'    // AO sign-off (draft → active)
  | 'retire:compensating_control';     // retire an active control

const PERMISSIONS_BY_ROLE: Record<Role, ReadonlySet<Permission>> = {
  viewer:       new Set(['read:items', 'read:risk_acceptance', 'read:compensating_control']),
  contributor:  new Set(['read:items', 'edit:items:assigned', 'read:risk_acceptance', 'read:compensating_control']),
  'ksi-owner':  new Set(['read:items', 'edit:items:assigned', 'edit:items:domain', 'read:risk_acceptance', 'read:compensating_control']),
  auditor:      new Set(['read:items', 'read:audit_log', 'read:risk_acceptance', 'read:compensating_control']),
  // iso creates + revokes deviation requests but cannot self-approve. For B.B4 the
  // iso implements (creates/edits) compensating controls + may retire them, but
  // cannot activate (AO sign-off is the separation-of-duties gate).
  iso:          new Set(['read:items', 'read:risk_acceptance', 'create:risk_acceptance', 'revoke:risk_acceptance',
                         'read:compensating_control', 'create:compensating_control', 'retire:compensating_control']),
  // ao is the approval authority; may also revoke. For B.B4 the ao activates a
  // compensating control (writes the second signature) + may retire.
  ao:           new Set(['read:items', 'read:risk_acceptance', 'approve:risk_acceptance', 'revoke:risk_acceptance',
                         'read:compensating_control', 'activate:compensating_control', 'retire:compensating_control']),
  // assessor (3PAO) is strictly read-only.
  assessor:     new Set(['read:items', 'read:risk_acceptance', 'read:compensating_control']),
  admin:        new Set(['read:items', 'edit:items:assigned', 'edit:items:domain', 'edit:items:all',
                         'manage:tokens', 'manage:users', 'read:audit_log', 'manage:2fa_policy',
                         'read:risk_acceptance', 'create:risk_acceptance', 'approve:risk_acceptance', 'revoke:risk_acceptance',
                         'read:compensating_control', 'create:compensating_control', 'activate:compensating_control', 'retire:compensating_control']),
};

/** Map legacy 'member'/'admin' to granular roles for back-compat. */
export function normalizeRole(stored: string | null | undefined): Role {
  if (!stored) return 'contributor';
  if (stored === 'admin') return 'admin';
  if (stored === 'member') return 'contributor';
  if ((ROLES as string[]).includes(stored)) return stored as Role;
  return 'contributor';
}

export function hasPermission(role: Role, perm: Permission): boolean {
  return PERMISSIONS_BY_ROLE[role]?.has(perm) ?? false;
}

/**
 * Compute effective permission for editing a specific item, honoring
 * owner + domain assignments.
 */
export interface EditContext {
  itemDomain?: string;      // e.g. "IAM" extracted from "KSI-IAM-MFA"
  itemOwnerUserId?: number; // FK from item_state.owner_user_id
}

export function canEditItem(userId: number, role: Role, ctx: EditContext): boolean {
  if (hasPermission(role, 'edit:items:all')) return true;
  if (hasPermission(role, 'edit:items:assigned') && ctx.itemOwnerUserId === userId) return true;
  if (hasPermission(role, 'edit:items:domain') && ctx.itemDomain) {
    return userAssignedToDomain(userId, ctx.itemDomain);
  }
  return false;
}

// ---- Domain assignments ----

export function ensureDomainTable(): void {
  db().exec(`
    CREATE TABLE IF NOT EXISTS user_domain_assignments (
      user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      domain   TEXT NOT NULL,    -- e.g. "IAM", "MLA"
      assigned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, domain)
    );
    CREATE INDEX IF NOT EXISTS idx_uda_domain ON user_domain_assignments(domain);
  `);
}

export function assignDomain(userId: number, domain: string, byUserId: number | null): void {
  ensureDomainTable();
  db().prepare(
    `INSERT OR IGNORE INTO user_domain_assignments (user_id, domain, assigned_by) VALUES (?, ?, ?)`,
  ).run(userId, domain.toUpperCase(), byUserId);
  // Audit
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'rbac', 'domain_assigned', NULL, ?)`,
  ).run(byUserId, `user:${userId}`, domain.toUpperCase());
}

export function unassignDomain(userId: number, domain: string, byUserId: number | null): void {
  ensureDomainTable();
  db().prepare(`DELETE FROM user_domain_assignments WHERE user_id = ? AND domain = ?`).run(userId, domain.toUpperCase());
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'rbac', 'domain_unassigned', ?, NULL)`,
  ).run(byUserId, `user:${userId}`, domain.toUpperCase());
}

export function userAssignedToDomain(userId: number, domain: string): boolean {
  ensureDomainTable();
  const row = db().prepare(`SELECT 1 AS x FROM user_domain_assignments WHERE user_id = ? AND domain = ?`)
    .get(userId, domain.toUpperCase());
  return !!row;
}

export function listUserDomains(userId: number): string[] {
  ensureDomainTable();
  return (db().prepare(`SELECT domain FROM user_domain_assignments WHERE user_id = ? ORDER BY domain`)
    .all(userId) as Array<{ domain: string }>).map((r) => r.domain);
}

// ---- Role change with audit log ----

export function changeRole(targetUserId: number, newRole: Role, byUserId: number | null): void {
  if (!ROLES.includes(newRole)) throw new Error(`invalid role: ${newRole}`);
  const oldRow = db().prepare(`SELECT role FROM users WHERE id = ?`).get(targetUserId) as { role?: string } | undefined;
  db().prepare(`UPDATE users SET role = ? WHERE id = ?`).run(newRole, targetUserId);
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, 'rbac', 'role', ?, ?)`,
  ).run(byUserId, `user:${targetUserId}`, oldRow?.role ?? null, newRole);
}

// ---- Middleware ----

export function requirePermission(perm: Permission): MiddlewareHandler {
  return async (c, next) => {
    const u = c.get('user') as any;
    if (!u) return c.json({ error: 'unauthorized' }, 401);
    const role = normalizeRole(u.role);
    if (!hasPermission(role, perm)) {
      return c.json({ error: 'forbidden', required_permission: perm, your_role: role }, 403);
    }
    return next();
  };
}

/** Extract the KSI domain from an item ID like "KSI-IAM-MFA" or "indicator:KSI-IAM-MFA". */
export function domainFromItemId(itemId: string): string | undefined {
  const m = itemId.match(/KSI-([A-Z]+)-/);
  return m?.[1];
}
