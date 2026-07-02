/**
 * Tests for server/routes/risk-acceptance.ts — the LOOP-B.B3 workflow API:
 * create/list/detail/verify/approve/revoke + RBAC (iso/ao/assessor) + signing.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';

// Mutable acting user; individual tests flip this before making a request.
const testAuth = vi.hoisted(() => ({ user: { id: 1, email: 'iso@x', name: 'ISO', role: 'iso' } as { id: number; email: string; name: string; role: string } }));

vi.mock('../auth.ts', async () => {
  const real = await vi.importActual<any>('../auth.ts');
  return {
    ...real,
    requireAuth: async (c: any, next: any) => { c.set('user', testAuth.user); return next(); },
  };
});

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-raroutes-'));
  process.env.DB_PATH = resolve(tmpDir, 'routes-test.db');
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function asIso() { testAuth.user = { id: 1, email: 'iso@x', name: 'ISO', role: 'iso' }; }
function asAo() { testAuth.user = { id: 2, email: 'ao@x', name: 'AO', role: 'ao' }; }
function asAssessor() { testAuth.user = { id: 3, email: 'assessor@x', name: 'ASSR', role: 'assessor' }; }

async function mkApp(): Promise<Hono> {
  const { db } = await import('../db.ts');
  const d = db();
  d.prepare('DELETE FROM risk_acceptance_compensating_links').run();
  d.prepare('DELETE FROM risk_acceptances').run();
  d.prepare('DELETE FROM audit_log').run();
  d.prepare('DELETE FROM users').run();
  for (const [id, email, role] of [[1, 'iso@x', 'iso'], [2, 'ao@x', 'ao'], [3, 'assessor@x', 'assessor'], [4, 'admin@x', 'admin']] as const) {
    d.prepare(`INSERT INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, 'x', ?)`).run(id, email, email, role);
  }
  const { riskAcceptanceRoutes } = await import('./risk-acceptance.ts');
  const app = new Hono();
  app.route('/', riskAcceptanceRoutes);
  return app;
}

function inDays(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

function validBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    finding_uuid: 'finding-1',
    poam_item_uuid: 'poam-1',
    ksi_id: 'KSI-IAM-MFA',
    rule: 'iam-mfa-aws-root',
    provider: 'aws',
    expiration_date: inDays(90),
    business_justification: 'We accept this residual risk because the root account is locked in a break-glass vault with hardware MFA and 24/7 alerting.',
    acceptance_type: 'risk-adjustment',
    compensating_control_uuids: [],
    ...over,
  };
}

async function post(app: Hono, path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request(`http://localhost${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }));
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
async function get(app: Hono, path: string): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request(`http://localhost${path}`));
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

beforeEach(() => { asIso(); });

describe('POST /risk-acceptances (create)', () => {
  it('creates a pending acceptance when iso submits a valid body', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody());
    expect(r.status).toBe(201);
    expect(r.body.acceptance.status).toBe('pending');
    expect(r.body.acceptance.signature.length).toBeGreaterThan(0);
    expect(r.body.acceptance.uuid).toMatch(/[0-9a-f-]{36}/);
  });

  it('rejects expiration_date < 7 days from now', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ expiration_date: inDays(3) }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('expiration_too_soon');
  });

  it('rejects expiration_date > 365 days from now', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ expiration_date: inDays(400) }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('expiration_too_far');
  });

  it('rejects justification < 100 chars', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ business_justification: 'too short' }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('justification_too_short');
  });

  it('rejects when the user lacks the iso role (assessor)', async () => {
    const app = await mkApp();
    asAssessor();
    const r = await post(app, '/', validBody());
    expect(r.status).toBe(403);
  });

  it('rejects a deviation-request with empty compensating_control_uuids', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ acceptance_type: 'deviation-request', compensating_control_uuids: [] }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('compensating_control_required');
  });

  it('signs the canonical JSON with the tracker Ed25519 key (verifiable)', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody({ acceptance_type: 'deviation-request', compensating_control_uuids: ['cc-1', 'cc-2'] }));
    expect(created.status).toBe(201);
    const uuid = created.body.acceptance.uuid;
    const v = await get(app, `/${uuid}/verify`);
    expect(v.status).toBe(200);
    expect(v.body.valid).toBe(true);
  });
});

describe('approve flow', () => {
  it('allows ao to transition pending -> approved with a second signature + audit row', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    asAo();
    const r = await post(app, `/${uuid}/approve`, {});
    expect(r.status).toBe(200);
    expect(r.body.acceptance.status).toBe('approved');
    expect(r.body.acceptance.approval_signature.length).toBeGreaterThan(0);
    expect(r.body.acceptance.approved_by_user_id).toBe(2);
    const { db } = await import('../db.ts');
    const audit = db().prepare(`SELECT * FROM audit_log WHERE item_id=? AND field='approved'`).get(`acceptance:${uuid}`);
    expect(audit).toBeTruthy();
  });

  it('rejects re-approving an already-approved acceptance (409)', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    asAo();
    expect((await post(app, `/${uuid}/approve`, {})).status).toBe(200);
    const second = await post(app, `/${uuid}/approve`, {});
    expect(second.status).toBe(409);
    expect(second.body.error).toBe('not_pending');
  });

  it('rejects a non-ao user (iso) from approving (403)', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    asIso();
    const r = await post(app, `/${uuid}/approve`, {});
    expect(r.status).toBe(403);
  });
});

describe('revoke flow', () => {
  it('allows revoke with a reason >= 30 chars and audits it', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    const r = await post(app, `/${uuid}/revoke`, { revocation_reason: 'Superseded by a permanent remediation deployed this sprint.' });
    expect(r.status).toBe(200);
    expect(r.body.acceptance.status).toBe('revoked');
  });

  it('rejects revoke with a reason < 30 chars', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    const r = await post(app, `/${uuid}/revoke`, { revocation_reason: 'too short' });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('reason_too_short');
  });
});

describe('RBAC + read paths', () => {
  it('assessor can GET the list but cannot POST', async () => {
    const app = await mkApp();
    // Seed one acceptance as iso first.
    await post(app, '/', validBody());
    asAssessor();
    const list = await get(app, '/?status=pending');
    expect(list.status).toBe(200);
    expect(Array.isArray(list.body.items)).toBe(true);
    expect(typeof list.body.public_key).toBe('string');
    const denied = await post(app, '/', validBody());
    expect(denied.status).toBe(403);
  });

  it('GET /:uuid returns the full signed payload including audit history', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.acceptance.uuid;
    const r = await get(app, `/${uuid}`);
    expect(r.status).toBe(200);
    expect(r.body.acceptance.signature.length).toBeGreaterThan(0);
    expect(Array.isArray(r.body.audit)).toBe(true);
    expect(r.body.audit.length).toBeGreaterThanOrEqual(1);
  });
});
