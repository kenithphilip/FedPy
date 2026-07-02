import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { db } from './db.ts';
import { csrfMiddleware, csrfTokenEndpoint } from './csrf.ts';
import { authRoutes } from './routes/auth.ts';
import { itemRoutes } from './routes/items.ts';
import { dashboardRoutes } from './routes/dashboard.ts';
import { exportRoutes } from './routes/export.ts';
import { tokenRoutes } from './routes/tokens.ts';
import { collectorRunRoutes } from './routes/collector_runs.ts';
import { twoFaRoutes } from './routes/2fa.ts';
import { auditRoutes } from './routes/audit.ts';
import { adminRoutes } from './routes/admin.ts';
import { attachmentRoutes } from './routes/attachments.ts';
import { riskAcceptanceRoutes } from './routes/risk-acceptance.ts';
import { compensatingControlRoutes } from './routes/compensating-controls.ts';
import { startRiskAcceptanceEnforcer } from './risk-acceptance-enforcer.ts';

// Initialize DB / schema
db();

const app = new Hono();

app.get('/api/health', (c) => c.json({ ok: true }));
app.get('/api/csrf-token', csrfTokenEndpoint);

// Serve the OpenAPI spec from disk so clients (Swagger UI, codegen, curl) can
// fetch the current contract. We read on every request so a dev edit shows up
// immediately; the file is small.
app.get('/api/openapi.yaml', async (c) => {
  const { readFileSync } = await import('node:fs');
  const { resolve: r } = await import('node:path');
  try {
    const yaml = readFileSync(r(import.meta.dirname ?? '.', 'openapi.yaml'), 'utf8');
    return c.body(yaml, 200, { 'content-type': 'application/yaml; charset=utf-8' });
  } catch (e: any) {
    return c.json({ error: 'openapi_spec_missing', message: e.message }, 404);
  }
});

// CSRF protection: enforced on all state-changing routes except auth bootstrap
// (where there's no session yet) and Bearer-token requests (which the middleware
// detects via the Authorization header).
app.use(
  '/api/*',
  csrfMiddleware({
    skipPaths: ['/api/auth/login', '/api/auth/signup', '/api/auth/bootstrap', '/api/csrf-token'],
  }),
);

app.route('/api/auth', authRoutes);
app.route('/api', itemRoutes);
app.route('/api', dashboardRoutes);
app.route('/api', exportRoutes);
app.route('/api/auth', tokenRoutes);
app.route('/api', collectorRunRoutes);
app.route('/api/2fa', twoFaRoutes);
app.route('/api/audit', auditRoutes);
app.route('/api/users', adminRoutes);
app.route('/api', attachmentRoutes);
app.route('/api/risk-acceptances', riskAcceptanceRoutes);
app.route('/api/compensating-controls', compensatingControlRoutes);

// LOOP-B.B3: boot the risk-acceptance expiry enforcer (runs immediately + hourly).
startRiskAcceptanceEnforcer();

// Serve built client in production
const clientDist = resolve(process.cwd(), 'client/dist');
if (existsSync(clientDist)) {
  app.use('/*', serveStatic({ root: './client/dist' }));
  app.get('*', serveStatic({ path: './client/dist/index.html' }));
}

const port = Number(process.env.PORT ?? 4000);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`tracker API listening on http://localhost:${info.port}`);
});
