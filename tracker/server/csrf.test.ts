/**
 * Tests for server/csrf.ts — double-submit cookie middleware.
 *
 * Builds a minimal Hono app, exercises GET/POST with various cookie/header
 * combinations, and asserts 200 vs 403 outcomes.
 */
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { csrfMiddleware } from './csrf.ts';

function makeApp() {
  const app = new Hono();
  app.use('*', csrfMiddleware({ skipPaths: ['/skip'] }));
  app.get('/data', (c) => c.json({ ok: true }));
  app.post('/mutate', (c) => c.json({ ok: true }));
  app.post('/skip', (c) => c.json({ ok: true }));
  return app;
}

async function call(app: Hono, method: string, path: string, headers: Record<string, string> = {}) {
  const req = new Request(`http://localhost${path}`, { method, headers });
  return app.fetch(req);
}

describe('csrfMiddleware', () => {
  it('allows GET requests without CSRF', async () => {
    const app = makeApp();
    const r = await call(app, 'GET', '/data');
    expect(r.status).toBe(200);
  });

  it('rejects POST with no CSRF cookie or header', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate');
    expect(r.status).toBe(403);
    expect((await r.json() as any).error).toBe('csrf_missing');
  });

  it('rejects POST with header but no cookie', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate', { 'X-CSRF-Token': 'abc123' });
    expect(r.status).toBe(403);
    expect((await r.json() as any).error).toBe('csrf_missing');
  });

  it('rejects POST with mismatched header and cookie', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate', {
      cookie: 'fr20x_csrf=abc123',
      'X-CSRF-Token': 'different',
    });
    expect(r.status).toBe(403);
    expect((await r.json() as any).error).toBe('csrf_mismatch');
  });

  it('allows POST with matching header and cookie', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate', {
      cookie: 'fr20x_csrf=secret-token',
      'X-CSRF-Token': 'secret-token',
    });
    expect(r.status).toBe(200);
  });

  it('exempts Bearer-token requests from CSRF (API tokens)', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate', {
      Authorization: 'Bearer cev_some-token',
    });
    expect(r.status).toBe(200);
  });

  it('skips configured skipPaths', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/skip');
    expect(r.status).toBe(200);
  });

  it('uses timing-safe comparison (mismatched lengths rejected cleanly)', async () => {
    const app = makeApp();
    const r = await call(app, 'POST', '/mutate', {
      cookie: 'fr20x_csrf=short',
      'X-CSRF-Token': 'much-longer-token',
    });
    expect(r.status).toBe(403);
    expect((await r.json() as any).error).toBe('csrf_mismatch');
  });

  it('rejects a duplicated (comma-joined) X-CSRF-Token header explicitly', async () => {
    const app = makeApp();
    // Node joins repeated headers with ", ". Even though the cookie matches the
    // first value, the duplicate must be rejected with a clear error.
    const r = await call(app, 'POST', '/mutate', {
      cookie: 'fr20x_csrf=secret-token',
      'X-CSRF-Token': 'secret-token, secret-token',
    });
    expect(r.status).toBe(403);
    expect((await r.json() as any).error).toBe('csrf_duplicate');
  });
});
