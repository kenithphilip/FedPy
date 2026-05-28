/**
 * Tests for server/rbac.ts — role permissions, domain assignments, audit log.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-rbac-'));
  process.env.DB_PATH = resolve(tmpDir, 'rbac-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('normalizeRole', () => {
  it('maps legacy admin/member to granular roles', async () => {
    const { normalizeRole } = await import('./rbac.ts');
    expect(normalizeRole('admin')).toBe('admin');
    expect(normalizeRole('member')).toBe('contributor');
    expect(normalizeRole(null)).toBe('contributor');
    expect(normalizeRole(undefined)).toBe('contributor');
  });

  it('passes through granular roles', async () => {
    const { normalizeRole } = await import('./rbac.ts');
    expect(normalizeRole('viewer')).toBe('viewer');
    expect(normalizeRole('ksi-owner')).toBe('ksi-owner');
    expect(normalizeRole('auditor')).toBe('auditor');
  });

  it('falls back to contributor for unknown roles', async () => {
    const { normalizeRole } = await import('./rbac.ts');
    expect(normalizeRole('xxx')).toBe('contributor');
  });
});

describe('hasPermission', () => {
  it('viewer can read but not edit', async () => {
    const { hasPermission } = await import('./rbac.ts');
    expect(hasPermission('viewer', 'read:items')).toBe(true);
    expect(hasPermission('viewer', 'edit:items:assigned')).toBe(false);
    expect(hasPermission('viewer', 'manage:users')).toBe(false);
  });

  it('admin has every permission', async () => {
    const { hasPermission } = await import('./rbac.ts');
    for (const p of ['read:items', 'edit:items:assigned', 'edit:items:domain', 'edit:items:all',
                     'manage:tokens', 'manage:users', 'read:audit_log', 'manage:2fa_policy'] as const) {
      expect(hasPermission('admin', p), p).toBe(true);
    }
  });

  it('ksi-owner has edit:items:domain but not edit:items:all', async () => {
    const { hasPermission } = await import('./rbac.ts');
    expect(hasPermission('ksi-owner', 'edit:items:domain')).toBe(true);
    expect(hasPermission('ksi-owner', 'edit:items:all')).toBe(false);
  });

  it('auditor has read:audit_log', async () => {
    const { hasPermission } = await import('./rbac.ts');
    expect(hasPermission('auditor', 'read:audit_log')).toBe(true);
    expect(hasPermission('auditor', 'edit:items:assigned')).toBe(false);
  });
});

describe('canEditItem', () => {
  it('admin can edit anything regardless of assignment', async () => {
    const { canEditItem } = await import('./rbac.ts');
    expect(canEditItem(1, 'admin', { itemDomain: 'IAM' })).toBe(true);
    expect(canEditItem(1, 'admin', { itemOwnerUserId: 42 })).toBe(true);
  });

  it('contributor can edit only items they own', async () => {
    const { canEditItem } = await import('./rbac.ts');
    expect(canEditItem(7, 'contributor', { itemOwnerUserId: 7 })).toBe(true);
    expect(canEditItem(7, 'contributor', { itemOwnerUserId: 9 })).toBe(false);
    expect(canEditItem(7, 'contributor', { itemDomain: 'IAM' })).toBe(false);
  });

  it('viewer cannot edit anything', async () => {
    const { canEditItem } = await import('./rbac.ts');
    expect(canEditItem(1, 'viewer', { itemOwnerUserId: 1 })).toBe(false);
    expect(canEditItem(1, 'viewer', { itemDomain: 'IAM' })).toBe(false);
  });
});

describe('domain assignments', () => {
  it('seeds the table on first use and persists assignments', async () => {
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(100, 'iam@example.com', 'IAM Owner', 'x', 'ksi-owner');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(200, 'admin@example.com', 'Admin', 'x', 'admin');

    const rbac = await import('./rbac.ts');
    rbac.assignDomain(100, 'iam', 200);
    expect(rbac.userAssignedToDomain(100, 'IAM')).toBe(true);
    expect(rbac.userAssignedToDomain(100, 'MLA')).toBe(false);
    expect(rbac.listUserDomains(100)).toEqual(['IAM']);
  });

  it('ksi-owner with IAM assignment can edit a KSI-IAM-MFA item', async () => {
    const rbac = await import('./rbac.ts');
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(101, 'iamowner2@example.com', 'IAM Owner 2', 'x', 'ksi-owner');
    rbac.assignDomain(101, 'IAM', 200);
    expect(rbac.canEditItem(101, 'ksi-owner', { itemDomain: 'IAM' })).toBe(true);
    expect(rbac.canEditItem(101, 'ksi-owner', { itemDomain: 'MLA' })).toBe(false);
  });

  it('domainFromItemId extracts domain from KSI ID', async () => {
    const { domainFromItemId } = await import('./rbac.ts');
    expect(domainFromItemId('KSI-IAM-MFA')).toBe('IAM');
    expect(domainFromItemId('KSI-MLA-EVC')).toBe('MLA');
    expect(domainFromItemId('not-a-ksi')).toBeUndefined();
  });

  it('audit log records role changes', async () => {
    const rbac = await import('./rbac.ts');
    const { db } = await import('./db.ts');
    db().prepare(`INSERT OR IGNORE INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, ?, ?)`)
      .run(300, 'changeme@example.com', 'Change Me', 'x', 'contributor');
    rbac.changeRole(300, 'auditor', 200);
    const row = db().prepare(`SELECT old_value, new_value FROM audit_log WHERE item_id = 'user:300' AND field = 'role' ORDER BY id DESC LIMIT 1`).get() as any;
    expect(row?.old_value).toBe('contributor');
    expect(row?.new_value).toBe('auditor');
  });
});
