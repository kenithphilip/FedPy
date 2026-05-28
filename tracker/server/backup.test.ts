/**
 * Tests for server/backup.ts — backup + restore + list + prune.
 *
 * Verifies a full roundtrip: seed → backup → modify DB → restore → DB matches
 * the original snapshot.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, rmSync, statSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-bkp-'));
  process.env.DB_PATH = resolve(tmpDir, 'bkp-test.db');
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('backup + restore roundtrip', () => {
  it('captures and restores DB state exactly', async () => {
    const { db } = await import('./db.ts');
    const { backup, restore } = await import('./backup.ts');

    // Seed
    db().prepare(`INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)`).run(
      'alice@example.com', 'Alice', 'placeholder', 'admin',
    );

    const backupDir = resolve(tmpDir, 'backups');
    const r1 = await backup(backupDir);
    expect(r1.bytes_compressed).toBeGreaterThan(0);
    expect(r1.bytes_compressed).toBeLessThan(r1.bytes_uncompressed);

    // Modify the live DB after the snapshot
    db().prepare(`INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, ?)`).run(
      'bob@example.com', 'Bob', 'x', 'member',
    );
    expect((db().prepare('SELECT COUNT(*) AS c FROM users').get() as any).c).toBeGreaterThanOrEqual(2);

    // Restore — should bring us back to the snapshot (only alice)
    const r = restore({ backupPath: r1.path });
    expect(r.integrity).toBe('ok');

    const count = (db().prepare(`SELECT COUNT(*) AS c FROM users`).get() as any).c;
    expect(count).toBe(1);
    const row = db().prepare(`SELECT email FROM users LIMIT 1`).get() as any;
    expect(row?.email).toBe('alice@example.com');
  });
});

describe('restore — defensive behavior', () => {
  it('refuses to restore over a symlink (prevents arbitrary-file overwrite)', async () => {
    const { backup, restore } = await import('./backup.ts');
    const fs = await import('node:fs');
    const backupDir = resolve(tmpDir, 'symlink-test');
    const r = await backup(backupDir);
    // Create a symlink at a "target" location pointing to a sensitive file.
    const fakeSensitive = resolve(tmpDir, 'fake-sensitive.conf');
    fs.writeFileSync(fakeSensitive, 'do-not-overwrite-me');
    const symlinkTarget = resolve(tmpDir, 'attacker-target.db');
    fs.symlinkSync(fakeSensitive, symlinkTarget);
    expect(() => restore({ backupPath: r.path, dbPath: symlinkTarget })).toThrow(/symlink/);
    // Confirm fake-sensitive is untouched
    expect(fs.readFileSync(fakeSensitive, 'utf8')).toBe('do-not-overwrite-me');
  });

  it('clear error on truncated gzip backup', async () => {
    const fs = await import('node:fs');
    const truncated = resolve(tmpDir, 'truncated.db.gz');
    fs.writeFileSync(truncated, Buffer.from([0x1f, 0x8b, 0x08, 0x00]));  // gzip header only
    const { restore } = await import('./backup.ts');
    expect(() => restore({ backupPath: truncated, dbPath: resolve(tmpDir, 'restore-target.db') }))
      .toThrow(/decompress/);
  });

  it('refuses to restore a file that is not a SQLite database (bad magic header)', async () => {
    const fs = await import('node:fs');
    const zlib = await import('node:zlib');
    // Valid gzip, but the decompressed content is not a SQLite DB.
    const notDb = resolve(tmpDir, 'not-a-db.db.gz');
    fs.writeFileSync(notDb, zlib.gzipSync(Buffer.from('this is plainly not a sqlite database file')));
    const { restore } = await import('./backup.ts');
    const target = resolve(tmpDir, 'magic-target.db');
    fs.writeFileSync(target, 'original-precious-data');
    expect(() => restore({ backupPath: notDb, dbPath: target })).toThrow(/not a valid SQLite database/);
    // The original target must be left intact (we validate before clobbering).
    expect(fs.readFileSync(target, 'utf8')).toBe('original-precious-data');
  });
});

describe('listBackups + pruneBackups', () => {
  it('lists existing backups newest-first', async () => {
    const { listBackups, backup } = await import('./backup.ts');
    const dir = resolve(tmpDir, 'list-test');
    const a = await backup(dir);
    // Small wait to differentiate mtimes by at least 1ms then create another
    await new Promise((r) => setTimeout(r, 5));
    const b = await backup(dir);
    const entries = listBackups(dir);
    expect(entries.length).toBe(2);
    // Newest first
    expect(entries[0]!.path).toBe(b.path);
    expect(entries[1]!.path).toBe(a.path);
  });

  it('prunes backups older than the cutoff', async () => {
    const { backup, listBackups, pruneBackups } = await import('./backup.ts');
    const dir = resolve(tmpDir, 'prune-test');
    const old = await backup(dir);

    // Backdate file mtime by 60 days
    const ageMs = 60 * 86400_000;
    const past = (Date.now() - ageMs) / 1000;
    utimesSync(old.path, past, past);

    const fresh = await backup(dir);
    expect(listBackups(dir).length).toBe(2);

    const removed = pruneBackups(dir, 30);
    expect(removed).toBe(1);
    const after = listBackups(dir);
    expect(after.length).toBe(1);
    expect(after[0]!.path).toBe(fresh.path);
  });
});
