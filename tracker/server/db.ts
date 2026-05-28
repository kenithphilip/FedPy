import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const DB_PATH = process.env.DB_PATH ?? join(process.cwd(), 'data', 'tracker.db');

let _db: Database.Database | null = null;

/**
 * How long (ms) SQLite waits on a locked DB before returning SQLITE_BUSY.
 * Under WAL a writer can still briefly block on the checkpoint lock; a busy
 * timeout makes concurrent requests retry internally instead of erroring out.
 */
const BUSY_TIMEOUT_MS = Number(process.env.TRACKER_DB_BUSY_TIMEOUT_MS ?? 5000);

export function db(): Database.Database {
  if (_db) return _db;
  let conn: Database.Database;
  try {
    conn = new Database(DB_PATH);
  } catch (e: any) {
    // Open failures (missing dir, EACCES, locked by another process) are fatal
    // but the raw better-sqlite3 message is cryptic — make it actionable.
    const hint = e?.code === 'SQLITE_CANTOPEN'
      ? ` Ensure the directory for DB_PATH exists and is writable (DB_PATH=${DB_PATH}).`
      : '';
    throw new Error(`Failed to open tracker database at ${DB_PATH}: ${e?.message ?? String(e)}.${hint}`);
  }
  try {
    conn.pragma(`busy_timeout = ${Number.isFinite(BUSY_TIMEOUT_MS) && BUSY_TIMEOUT_MS > 0 ? BUSY_TIMEOUT_MS : 5000}`);
    conn.pragma('journal_mode = WAL');
    conn.pragma('foreign_keys = ON');
    const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf8');
    conn.exec(schema);
    migrate(conn);
    // Startup health check: a trivial query confirms the file is a usable DB
    // (not truncated/corrupt) before we hand the connection to request paths.
    const health = conn.prepare('SELECT 1 AS ok').get() as { ok?: number } | undefined;
    if (health?.ok !== 1) throw new Error('database health check failed (SELECT 1 did not return 1)');
  } catch (e) {
    // Don't leak a half-initialized handle if setup failed.
    try { conn.close(); } catch { /* ignore */ }
    throw e;
  }
  _db = conn;
  return _db;
}

/**
 * Idempotent additive migrations. SQLite's ALTER TABLE ADD COLUMN doesn't
 * support IF NOT EXISTS in the version we ship, so we introspect each table
 * first and only ALTER when the column is missing.
 */
function migrate(d: Database.Database): void {
  // D.3 — TOTP 2FA columns on users
  ensureColumn(d, 'users', 'totp_secret_b32', 'TEXT');
  ensureColumn(d, 'users', 'totp_enrolled_at', 'TEXT');
  ensureColumn(d, 'users', 'totp_backup_codes', 'TEXT');
  ensureColumn(d, 'users', 'require_2fa', 'INTEGER NOT NULL DEFAULT 0');

  // Post-audit fix — pre-auth sessions for 2FA-enrolled users.
  // When NULL, the session is fully authenticated. When set to a future
  // datetime, the session is only allowed to call /api/2fa/verify and /api/auth/logout.
  // /api/2fa/verify clears this on successful TOTP/backup-code submission.
  // After the deadline, the session is invalid.
  ensureColumn(d, 'sessions', 'preauth_until', 'TEXT');

  // Post-audit fix — atomic backup-code consumption.
  // Pre-audit code did a read-modify-write on users.totp_backup_codes which
  // let two concurrent /api/2fa/verify requests with the same code both
  // succeed (verified by the second audit pass). Switch to a separate
  // tracking table with a uniqueness constraint: INSERT ON CONFLICT DO NOTHING
  // returns 0 changes on duplicate, which we treat as "already used".
  d.exec(`
    CREATE TABLE IF NOT EXISTS totp_backup_codes_used (
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code_hash  TEXT    NOT NULL,
      used_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (user_id, code_hash)
    );
  `);

  // D.4 — relax users.role CHECK constraint to allow granular RBAC roles.
  // SQLite can't ALTER a CHECK constraint, so we use the standard
  // rename-create-copy-drop pattern. Idempotent: only runs if the old
  // CHECK is still present.
  relaxRoleCheck(d);

  // H.4 — Per-item attachments. Files are stored on disk under data/attachments/
  // by their SHA-256 hash to dedupe; this table holds the metadata.
  d.exec(`
    CREATE TABLE IF NOT EXISTS item_attachments (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id      TEXT NOT NULL,
      item_type    TEXT NOT NULL CHECK (item_type IN ('requirement','indicator')),
      uploaded_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
      uploaded_at  TEXT NOT NULL DEFAULT (datetime('now')),
      filename     TEXT NOT NULL,
      content_type TEXT NOT NULL,
      bytes        INTEGER NOT NULL,
      sha256       TEXT NOT NULL,
      storage_path TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_attach_item ON item_attachments(item_id, item_type);
    CREATE INDEX IF NOT EXISTS idx_attach_sha ON item_attachments(sha256);
  `);
}

function ensureColumn(d: Database.Database, table: string, column: string, typeSpec: string): void {
  const info = d.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (info.some((r) => r.name === column)) return;
  d.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${typeSpec}`);
}

function relaxRoleCheck(d: Database.Database): void {
  // Detect whether the old CHECK is still in place by inspecting sqlite_master.
  const row = d.prepare(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`).get() as { sql?: string } | undefined;
  const sql = row?.sql ?? '';
  if (!/CHECK\s*\(\s*role\s+IN\s*\(\s*'admin'\s*,\s*'member'\s*\)\s*\)/i.test(sql)) {
    return; // already migrated or never had the restrictive CHECK
  }

  // SQLite "rebuild" migration. We hard-code the new users table because the
  // PRAGMA table_info output doesn't preserve function-call defaults
  // (e.g. `datetime('now')` must be parenthesized in the recreate).
  d.exec('PRAGMA foreign_keys = OFF');
  // legacy_alter_table = ON tells SQLite NOT to rewrite FK references in
  // other tables when we RENAME users; without it, audit_log.user_id would
  // suddenly point at users__old and break when we drop the old table.
  d.exec('PRAGMA legacy_alter_table = ON');
  try {
    d.exec('BEGIN TRANSACTION');
    d.exec('ALTER TABLE users RENAME TO users__old');
    d.exec(`
      CREATE TABLE users (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        email              TEXT NOT NULL UNIQUE,
        name               TEXT NOT NULL,
        password_hash      TEXT NOT NULL,
        role               TEXT NOT NULL DEFAULT 'member'
                              CHECK (role IN ('viewer','contributor','ksi-owner','auditor','admin','member')),
        created_at         TEXT NOT NULL DEFAULT (datetime('now')),
        totp_secret_b32    TEXT,
        totp_enrolled_at   TEXT,
        totp_backup_codes  TEXT,
        require_2fa        INTEGER NOT NULL DEFAULT 0
      )
    `);
    d.exec(`
      INSERT INTO users (id, email, name, password_hash, role, created_at,
                         totp_secret_b32, totp_enrolled_at, totp_backup_codes, require_2fa)
      SELECT id, email, name, password_hash, role, created_at,
             totp_secret_b32, totp_enrolled_at, totp_backup_codes, require_2fa
      FROM users__old
    `);
    d.exec('DROP TABLE users__old');
    d.exec('COMMIT');
  } catch (e) {
    d.exec('ROLLBACK');
    throw e;
  } finally {
    d.exec('PRAGMA legacy_alter_table = OFF');
    d.exec('PRAGMA foreign_keys = ON');
  }
}

export function closeDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}
