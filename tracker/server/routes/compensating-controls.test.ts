/**
 * Tests for server/routes/compensating-controls.ts — the LOOP-B.B4 registry API:
 * create/list/detail/verify/update/activate/retire + RBAC (iso/ao/assessor) +
 * NIST-catalog validation + Ed25519 signing + retirement guard (B.B4-4).
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Hono } from 'hono';

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
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-ccroutes-'));
  process.env.DB_PATH = resolve(tmpDir, 'cc-routes-test.db');
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
  d.prepare('DELETE FROM compensating_controls').run();
  d.prepare('DELETE FROM audit_log').run();
  d.prepare('DELETE FROM users').run();
  for (const [id, email, role] of [[1, 'iso@x', 'iso'], [2, 'ao@x', 'ao'], [3, 'assessor@x', 'assessor'], [4, 'admin@x', 'admin']] as const) {
    d.prepare(`INSERT INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, 'x', ?)`).run(id, email, email, role);
  }
  const { compensatingControlRoutes } = await import('./compensating-controls.ts');
  const app = new Hono();
  app.route('/', compensatingControlRoutes);
  return app;
}

function validBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    title: 'MFA break-glass vault',
    description: 'The root/break-glass account is stored in a hardware-MFA vault with 24/7 alerting and quarterly access reviews, providing equivalent protection to the recommended automated MFA control while the automated path is remediated. '.padEnd(220, '.'),
    nist_control_ids: ['AC-2', 'AC-2(3)', 'SC-7'],
    evidence_url: 'https://runbooks.example/break-glass',
    ...over,
  };
}

async function post(app: Hono, path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request(`http://localhost${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }));
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
async function put(app: Hono, path: string, body: unknown): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request(`http://localhost${path}`, {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  }));
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
async function get(app: Hono, path: string): Promise<{ status: number; body: any }> {
  const res = await app.fetch(new Request(`http://localhost${path}`));
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

beforeEach(() => { asIso(); });

describe('POST /compensating-controls (create)', () => {
  it('creates a draft compensating control when iso submits a valid body', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody());
    expect(r.status).toBe(201);
    expect(r.body.compensating_control.status).toBe('draft');
    expect(r.body.compensating_control.signature.length).toBeGreaterThan(0);
    expect(r.body.compensating_control.uuid).toMatch(/[0-9a-f-]{36}/);
    expect(r.body.compensating_control.nist_control_ids).toEqual(['AC-2', 'AC-2(3)', 'SC-7']);
  });

  it('rejects a title shorter than 5 or longer than 200 chars', async () => {
    const app = await mkApp();
    expect((await post(app, '/', validBody({ title: 'AB' }))).body.error).toBe('invalid_title');
    expect((await post(app, '/', validBody({ title: 'x'.repeat(201) }))).body.error).toBe('invalid_title');
  });

  it('rejects a description shorter than 200 chars', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ description: 'too short' }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('description_too_short');
  });

  it('rejects an invalid NIST control id and names the offending value', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ nist_control_ids: ['AC-2', 'AC-99'] }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('invalid_nist_control_id');
    expect(r.body.value).toBe('AC-99');
    expect(r.body.field).toBe('nist_control_ids');
  });

  it('rejects an empty nist_control_ids array', async () => {
    const app = await mkApp();
    const r = await post(app, '/', validBody({ nist_control_ids: [] }));
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('missing_nist_control_ids');
  });

  it('rejects when the user lacks the iso role (assessor)', async () => {
    const app = await mkApp();
    asAssessor();
    const r = await post(app, '/', validBody());
    expect(r.status).toBe(403);
  });

  it('signs the canonical JSON with the tracker Ed25519 key (verifiable)', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    const v = await get(app, `/${uuid}/verify`);
    expect(v.status).toBe(200);
    expect(v.body.valid).toBe(true);
  });
});

describe('activate flow', () => {
  it('rejects activation by a non-ao user (iso) with 403', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asIso();
    const r = await post(app, `/${uuid}/activate`, {});
    expect(r.status).toBe(403);
  });

  it('allows ao to transition draft -> active with a second signature + audit row', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    const r = await post(app, `/${uuid}/activate`, {});
    expect(r.status).toBe(200);
    expect(r.body.compensating_control.status).toBe('active');
    expect(r.body.compensating_control.signed_off_by_user_id).toBe(2);
    expect(r.body.compensating_control.activation_signature.length).toBeGreaterThan(0);
    const v = await get(app, `/${uuid}/verify`);
    expect(v.body.valid).toBe(true);
    expect(v.body.activation_valid).toBe(true);
    const { db } = await import('../db.ts');
    const audit = db().prepare(`SELECT * FROM audit_log WHERE item_id=? AND field='activated'`).get(`compensating-control:${uuid}`);
    expect(audit).toBeTruthy();
  });
});

describe('update (draft-only) + immutability', () => {
  it('allows editing a draft and re-signs it', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    const r = await put(app, `/${uuid}`, validBody({ title: 'MFA break-glass vault (v2)' }));
    expect(r.status).toBe(200);
    expect(r.body.compensating_control.title).toBe('MFA break-glass vault (v2)');
    const v = await get(app, `/${uuid}/verify`);
    expect(v.body.valid).toBe(true);
  });

  it('rejects a PUT on an active control (immutable — retire + recreate) with 409', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    await post(app, `/${uuid}/activate`, {});
    asIso();
    const r = await put(app, `/${uuid}`, validBody({ title: 'attempted edit' }));
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('not_draft');
  });

  it('rejects activation of an already-active control with 409', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    expect((await post(app, `/${uuid}/activate`, {})).status).toBe(200);
    const second = await post(app, `/${uuid}/activate`, {});
    expect(second.status).toBe(409);
    expect(second.body.error).toBe('not_draft');
  });
});

describe('retire flow', () => {
  it('allows iso to retire an active control with a reason >= 30 chars', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    await post(app, `/${uuid}/activate`, {});
    asIso();
    const r = await post(app, `/${uuid}/retire`, { retirement_reason: 'Superseded by the automated MFA control deployed this quarter.' });
    expect(r.status).toBe(200);
    expect(r.body.compensating_control.status).toBe('retired');
  });

  it('rejects retire with a reason < 30 chars', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    await post(app, `/${uuid}/activate`, {});
    asIso();
    const r = await post(app, `/${uuid}/retire`, { retirement_reason: 'too short' });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('reason_too_short');
  });

  it('refuses to retire a control still cited by an active acceptance (B.B4-4)', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    asAo();
    await post(app, `/${uuid}/activate`, {});
    // Wire up an approved acceptance that references this control.
    const { db } = await import('../db.ts');
    const info = db().prepare(
      `INSERT INTO risk_acceptances (uuid, finding_uuid, poam_item_uuid, ksi_id, rule, provider,
         accepted_by_user_id, accepted_at, expiration_date, business_justification, acceptance_type,
         status, signature, signing_key_id)
       VALUES ('acc-x','f','p','KSI-IAM-MFA','r','aws',1,'2026-07-02T00:00:00Z','2026-12-01T00:00:00Z',?,'deviation-request','approved','sig','k')`,
    ).run('j'.repeat(120));
    db().prepare(`INSERT INTO risk_acceptance_compensating_links (acceptance_id, compensating_control_uuid) VALUES (?, ?)`).run(Number(info.lastInsertRowid), uuid);
    asIso();
    const r = await post(app, `/${uuid}/retire`, { retirement_reason: 'Attempting to retire while an acceptance still cites it.' });
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('linked_acceptances_active');
  });
});

describe('list + uuid-exists', () => {
  it('lists only active controls when ?status=active', async () => {
    const app = await mkApp();
    const a = await post(app, '/', validBody({ title: 'control A' }));
    await post(app, '/', validBody({ title: 'control B' }));   // stays draft
    asAo();
    await post(app, `/${a.body.compensating_control.uuid}/activate`, {});
    asIso();
    const list = await get(app, '/?status=active');
    expect(list.status).toBe(200);
    expect(list.body.items.length).toBe(1);
    expect(list.body.items[0].title).toBe('control A');
    expect(typeof list.body.public_key).toBe('string');
  });

  it('uuid-exists reports true for a live control and false for an unknown uuid', async () => {
    const app = await mkApp();
    const created = await post(app, '/', validBody());
    const uuid = created.body.compensating_control.uuid;
    const r = await get(app, `/uuid-exists?uuids=${uuid},does-not-exist`);
    expect(r.status).toBe(200);
    expect(r.body.exists[uuid]).toBe(true);
    expect(r.body.exists['does-not-exist']).toBe(false);
  });
});
