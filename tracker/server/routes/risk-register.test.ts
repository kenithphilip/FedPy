/**
 * Tests for server/routes/risk-register.ts — the LOOP-B.B5 Central Risk Register:
 * organisational-risk CRUD + close-out + NIST-800-30 enum validation + server-side
 * inherent computation (Q5) + NIST-catalog + compensating-control cross-checks +
 * RBAC (iso/ao create; assessor read-only) + the aggregated register + XLSX export.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { Hono } from 'hono';

const testAuth = vi.hoisted(() => ({ user: { id: 1, email: 'iso@x', name: 'ISO User', role: 'iso' } as { id: number; email: string; name: string; role: string } }));

vi.mock('../auth.ts', async () => {
  const real = await vi.importActual<any>('../auth.ts');
  return { ...real, requireAuth: async (c: any, next: any) => { c.set('user', testAuth.user); return next(); } };
});

let tmpDir: string;
beforeAll(() => { tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-rrroutes-')); process.env.DB_PATH = resolve(tmpDir, 'rr-routes-test.db'); });
afterAll(() => { rmSync(tmpDir, { recursive: true, force: true }); });

function asIso() { testAuth.user = { id: 1, email: 'iso@x', name: 'ISO User', role: 'iso' }; }
function asAssessor() { testAuth.user = { id: 3, email: 'assessor@x', name: 'ASSR', role: 'assessor' }; }

async function mkApp(): Promise<Hono> {
  const { db } = await import('../db.ts');
  const d = db();
  d.prepare('DELETE FROM organisational_risks').run();
  d.prepare('DELETE FROM risk_acceptances').run();
  d.prepare('DELETE FROM compensating_controls').run();
  d.prepare('DELETE FROM audit_log').run();
  d.prepare('DELETE FROM users').run();
  for (const [id, email, role] of [[1, 'iso@x', 'iso'], [2, 'ao@x', 'ao'], [3, 'assessor@x', 'assessor'], [4, 'admin@x', 'admin']] as const) {
    d.prepare(`INSERT INTO users (id, email, name, password_hash, role) VALUES (?, ?, ?, 'x', ?)`).run(id, email, email, role);
  }
  const { organisationalRisksRoutes, riskRegisterRoutes } = await import('./risk-register.ts');
  const app = new Hono();
  app.route('/organisational-risks', organisationalRisksRoutes);
  app.route('/risk-register', riskRegisterRoutes);
  return app;
}

const future = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

function validBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    title: 'Key subprocessor bankruptcy risk',
    description: 'A tier-1 subprocessor faces financial distress that could disrupt the authorized service if it ceases operations. '.padEnd(140, '.'),
    category: 'third-party',
    likelihood: 'high',
    impact: 'very-high',
    residual_risk: 'moderate',
    treatment: 'mitigate',
    review_date: future(60),
    ...over,
  };
}

async function post(app: Hono, path: string, body: unknown) {
  return app.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

describe('POST /organisational-risks — validation + server-side inherent', () => {
  it('creates an organisational risk and computes inherent server-side (Q5)', async () => {
    asIso();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody());
    expect(res.status).toBe(201);
    const j = await res.json();
    // high × very-high = very-high (NIST 800-30 Table I-2).
    expect(j.organisational_risk.inherent_risk).toBe('very-high');
    expect(j.organisational_risk.status).toBe('open');
    expect(j.organisational_risk.owner).toBe('iso@x'); // seeded users have name = email
    expect(j.organisational_risk.residual_risk).toBe('moderate');
  });

  it('rejects an out-of-enum likelihood/impact (NIST 800-30 bands)', async () => {
    asIso();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody({ likelihood: 'catastrophic' }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_likelihood');
  });

  it('rejects a review_date less than 30 days in the future', async () => {
    asIso();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody({ review_date: future(5) }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('review_date_too_soon');
  });

  it('rejects POST when nist_control_ids include an unknown id', async () => {
    asIso();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody({ nist_control_ids: ['SA-9', 'ZZ-99'] }));
    expect(res.status).toBe(400);
    const j = await res.json();
    expect(j.error).toBe('invalid_nist_control_id');
    expect(j.value).toBe('ZZ-99');
  });

  it('rejects POST when compensating_control_uuids include an unknown uuid', async () => {
    asIso();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody({ compensating_control_uuids: ['no-such-uuid'] }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('unknown_compensating_control');
  });

  it('forbids an assessor (read-only) from creating', async () => {
    asAssessor();
    const app = await mkApp();
    const res = await post(app, '/organisational-risks', validBody());
    expect(res.status).toBe(403);
  });
});

describe('PUT + close lifecycle', () => {
  it('PUT updates an open risk; rejects updates on a closed risk', async () => {
    asIso();
    const app = await mkApp();
    const created = await (await post(app, '/organisational-risks', validBody())).json();
    const uuid = created.organisational_risk.uuid;

    const upd = await app.request(`/organisational-risks/${uuid}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(validBody({ likelihood: 'low', impact: 'low', residual_risk: 'very-low' })),
    });
    expect(upd.status).toBe(200);
    expect((await upd.json()).organisational_risk.inherent_risk).toBe('low'); // low × low = low

    const closed = await post(app, `/organisational-risks/${uuid}/close`, { closure_reason: 'Subprocessor was replaced with an authorized alternative.' });
    expect(closed.status).toBe(200);
    expect((await closed.json()).organisational_risk.status).toBe('closed');

    const updClosed = await app.request(`/organisational-risks/${uuid}`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(validBody()),
    });
    expect(updClosed.status).toBe(409);
    expect((await updClosed.json()).error).toBe('not_open');
  });

  it('POST /:uuid/close transitions status + records closure_reason; rejects a short reason', async () => {
    asIso();
    const app = await mkApp();
    const created = await (await post(app, '/organisational-risks', validBody())).json();
    const uuid = created.organisational_risk.uuid;
    const tooShort = await post(app, `/organisational-risks/${uuid}/close`, { closure_reason: 'nope' });
    expect(tooShort.status).toBe(400);
    const ok = await post(app, `/organisational-risks/${uuid}/close`, { closure_reason: 'Risk retired after vendor consolidation completed.' });
    expect(ok.status).toBe(200);
    const detail = await (await app.request(`/organisational-risks/${uuid}`)).json();
    expect(detail.organisational_risk.closure_reason).toContain('vendor consolidation');
    expect(detail.audit.some((a: any) => a.field === 'closed')).toBe(true);
  });
});

describe('aggregated register + XLSX export', () => {
  it('GET /risk-register returns aggregated entries (organisational + approved acceptance)', async () => {
    asIso();
    const app = await mkApp();
    await post(app, '/organisational-risks', validBody());
    // Seed an approved, unexpired acceptance directly.
    const { db } = await import('../db.ts');
    db().prepare(
      `INSERT INTO risk_acceptances (uuid, finding_uuid, poam_item_uuid, ksi_id, rule, provider, accepted_by_user_id,
         accepted_at, expiration_date, business_justification, acceptance_type, status, signature, signing_key_id)
       VALUES ('acc-1','f-1','pi-1','KSI-IAM-MFA','iam-mfa','aws',1,?,?,?,'risk-adjustment','approved','s','k')`,
    ).run(new Date().toISOString(), future(90), 'x'.repeat(120));

    const res = await app.request('/risk-register');
    expect(res.status).toBe(200);
    const j = await res.json();
    expect(j.summary.by_source.organisational).toBe(1);
    expect(j.summary.by_source.acceptance).toBe(1);
    expect(j.entries.some((e: any) => e.source === 'acceptance' && e.treatment === 'accept')).toBe(true);
    // Organisational entry (very-high inherent) sorts before/among the entries.
    expect(j.summary.high_inherent_count).toBeGreaterThanOrEqual(1);
  });

  it('GET /risk-register/export.xlsx streams a valid XLSX (store-only OOXML zip)', async () => {
    asIso();
    const app = await mkApp();
    await post(app, '/organisational-risks', validBody());
    const res = await app.request('/risk-register/export.xlsx');
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('spreadsheetml.sheet');
    const buf = Buffer.from(await res.arrayBuffer());
    // Valid zip local-file-header signature.
    expect(buf.readUInt32LE(0)).toBe(0x04034b50);
    // Pull the first part out and confirm it is a real OOXML container.
    const nameLen = buf.readUInt16LE(26);
    const name = buf.toString('utf8', 30, 30 + nameLen);
    expect(name).toBe('[Content_Types].xml');
    // Locate + inflate the sheet part to confirm the header row rendered.
    const parts: Record<string, string> = {};
    let i = 0;
    while (i + 4 <= buf.length && buf.readUInt32LE(i) === 0x04034b50) {
      const method = buf.readUInt16LE(i + 8);
      const comp = buf.readUInt32LE(i + 18);
      const nl = buf.readUInt16LE(i + 26);
      const el = buf.readUInt16LE(i + 28);
      const nm = buf.toString('utf8', i + 30, i + 30 + nl);
      const start = i + 30 + nl + el;
      const raw = buf.subarray(start, start + comp);
      parts[nm] = (method === 8 ? inflateRawSync(raw) : raw).toString('utf8');
      i = start + comp;
    }
    expect(parts['xl/worksheets/sheet1.xml']).toContain('Inherent Risk');
    expect(parts['xl/worksheets/sheet1.xml']).toContain('<pane ySplit="1"');
  });
});
