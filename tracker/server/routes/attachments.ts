/**
 * Per-item attachment routes.
 *
 *   GET    /api/items/:itemId/:itemType/attachments       — list
 *   POST   /api/items/:itemId/:itemType/attachments       — upload (multipart/form-data)
 *   GET    /api/attachments/:id                            — download (content-disposition)
 *   DELETE /api/items/:itemId/:itemType/attachments/:id   — delete (admin or uploader)
 *
 * Storage:
 *   - Files are written to `data/attachments/<sha256-first-2-hex>/<sha256>.bin`
 *     (sharded by first 2 hex chars to avoid huge directories).
 *   - The blob is content-addressed; duplicate uploads dedupe automatically.
 *   - The DB row keeps the original filename so downloads use that name.
 *
 * Safety:
 *   - 25 MB per-file cap (configurable via TRACKER_MAX_ATTACHMENT_MB).
 *   - MIME allowlist: PDF, PNG, JPEG, plaintext, JSON, CSV by default.
 *     Override with TRACKER_ATTACHMENT_MIME_ALLOWLIST (comma-separated).
 *   - Filenames are sanitized: drop everything except a-z A-Z 0-9 . - _ +.
 */
import { Hono } from 'hono';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync, readFileSync, statSync, unlinkSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { db } from '../db.ts';
import { requireAuth } from '../auth.ts';

const ATTACH_ROOT = process.env.TRACKER_ATTACHMENTS_DIR ?? resolve(process.cwd(), 'data', 'attachments');

/** Parse a positive-number env var with a clear startup-time error on garbage input. */
function envPositiveNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw == null || raw === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${name} must be a positive number; got "${raw}"`);
  }
  return n;
}

const MAX_BYTES = envPositiveNumber('TRACKER_MAX_ATTACHMENT_MB', 25) * 1024 * 1024;
const ALLOWED_MIME = (process.env.TRACKER_ATTACHMENT_MIME_ALLOWLIST ??
  'application/pdf,image/png,image/jpeg,image/gif,text/plain,application/json,text/csv,application/zip,application/x-yaml,text/yaml'
).split(',').map((s) => s.trim());

export const attachmentRoutes = new Hono();
attachmentRoutes.use('*', requireAuth);

export const MAX_FILENAME_LEN = 200;

export function sanitizeFilename(name: string): string {
  return name.replace(/[^A-Za-z0-9._+\-]/g, '_').slice(0, MAX_FILENAME_LEN) || 'attachment';
}

/**
 * Build a Content-Disposition value that is safe for ALL clients.
 *
 * We emit both the legacy ASCII `filename="..."` (with any residual quote/
 * control chars stripped) and the RFC 5987 `filename*=UTF-8''<pct-encoded>`
 * form so browsers render UTF-8 names correctly while older clients fall back
 * to the ASCII token. This also prevents header-injection: encodeURIComponent
 * removes CR/LF and quotes.
 */
export function contentDisposition(filename: string): string {
  const asciiFallback = filename.replace(/["\\\r\n]/g, '_');
  const encoded = encodeURIComponent(filename).replace(/['()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase());
  return `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encoded}`;
}

function storagePathFor(sha: string): string {
  return join(ATTACH_ROOT, sha.slice(0, 2), `${sha}.bin`);
}

// GET /api/items/:itemId/:itemType/attachments
attachmentRoutes.get('/items/:itemId/:itemType/attachments', (c) => {
  const itemId = c.req.param('itemId');
  const itemType = c.req.param('itemType');
  const rows = db().prepare(`
    SELECT a.id, a.filename, a.content_type, a.bytes, a.sha256, a.uploaded_at,
           u.email AS uploaded_by_email, u.name AS uploaded_by_name
    FROM item_attachments a
    LEFT JOIN users u ON u.id = a.uploaded_by
    WHERE a.item_id = ? AND a.item_type = ?
    ORDER BY a.uploaded_at DESC
  `).all(itemId, itemType);
  return c.json({ attachments: rows });
});

// POST /api/items/:itemId/:itemType/attachments — multipart/form-data
attachmentRoutes.post('/items/:itemId/:itemType/attachments', async (c) => {
  const itemId = c.req.param('itemId');
  const itemType = c.req.param('itemType');
  if (!['requirement', 'indicator'].includes(itemType)) {
    return c.json({ error: 'invalid item_type' }, 400);
  }

  let body: FormData;
  try {
    body = await c.req.formData();
  } catch (e: any) {
    return c.json({ error: 'expected multipart/form-data', detail: e.message }, 400);
  }
  const file = body.get('file');
  if (!(file instanceof File)) return c.json({ error: 'form field "file" required' }, 400);
  if (file.size > MAX_BYTES) return c.json({ error: `file exceeds ${MAX_BYTES / 1024 / 1024} MB limit` }, 413);
  if (!ALLOWED_MIME.includes(file.type)) {
    return c.json({ error: `MIME type ${file.type} not in allowlist`, allowed: ALLOWED_MIME }, 415);
  }

  const buf = Buffer.from(await file.arrayBuffer());
  const sha = createHash('sha256').update(buf).digest('hex');
  const filename = sanitizeFilename(file.name);
  // Signal truncation so the client can warn the user the stored name differs.
  const filenameTruncated = file.name.length > MAX_FILENAME_LEN;
  const storagePath = storagePathFor(sha);
  mkdirSync(dirname(storagePath), { recursive: true });
  if (!existsSync(storagePath)) writeFileSync(storagePath, buf);

  const user = c.get('user') as any;
  const info = db().prepare(`
    INSERT INTO item_attachments (item_id, item_type, uploaded_by, filename, content_type, bytes, sha256, storage_path)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(itemId, itemType, user?.id ?? null, filename, file.type, buf.length, sha, storagePath);

  // Audit log
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, ?, 'attachment_added', NULL, ?)`,
  ).run(user?.id ?? null, itemId, itemType, filename);

  return c.json({ id: Number(info.lastInsertRowid), filename, content_type: file.type, bytes: buf.length, sha256: sha, filename_truncated: filenameTruncated });
});

// GET /api/attachments/:id — download
attachmentRoutes.get('/attachments/:id', (c) => {
  const id = Number(c.req.param('id'));
  const row = db().prepare(`SELECT * FROM item_attachments WHERE id = ?`).get(id) as any;
  if (!row) return c.json({ error: 'not found' }, 404);
  if (!existsSync(row.storage_path)) return c.json({ error: 'blob missing from disk' }, 410);
  const buf = readFileSync(row.storage_path);
  return c.body(buf, 200, {
    'content-type': row.content_type,
    'content-length': String(row.bytes),
    'content-disposition': contentDisposition(row.filename),
  });
});

// DELETE /api/items/:itemId/:itemType/attachments/:id
attachmentRoutes.delete('/items/:itemId/:itemType/attachments/:id', (c) => {
  const itemId = c.req.param('itemId');
  const itemType = c.req.param('itemType');
  const id = Number(c.req.param('id'));
  const user = c.get('user') as any;

  const row = db().prepare(`SELECT * FROM item_attachments WHERE id = ? AND item_id = ? AND item_type = ?`).get(id, itemId, itemType) as any;
  if (!row) return c.json({ error: 'not found' }, 404);

  const isOwner = user?.id && row.uploaded_by === user.id;
  const isAdmin = user?.role === 'admin';
  if (!isOwner && !isAdmin) return c.json({ error: 'forbidden — only the uploader or an admin can delete' }, 403);

  db().prepare(`DELETE FROM item_attachments WHERE id = ?`).run(id);

  // Drop the blob ONLY if no other row references it (content-addressed dedupe)
  const stillReferenced = db().prepare(`SELECT 1 FROM item_attachments WHERE sha256 = ? LIMIT 1`).get(row.sha256);
  if (!stillReferenced) {
    try { unlinkSync(row.storage_path); } catch { /* best-effort */ }
  }

  // Audit
  db().prepare(
    `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
     VALUES (?, ?, ?, 'attachment_removed', ?, NULL)`,
  ).run(user?.id ?? null, itemId, itemType, row.filename);

  return c.json({ ok: true });
});
