/**
 * Tracker restore CLI.
 *
 * Usage:
 *   tsx scripts/restore.ts <backup-file>
 *   tsx scripts/restore.ts --db <db-path> <backup-file>
 *
 * IMPORTANT: stop the tracker server first. This script overwrites the DB.
 */
import { restore } from '../server/backup.ts';

function parseArgs(argv: string[]): { backupPath: string; dbPath?: string } {
  let dbPath: string | undefined;
  let backupPath: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--db') dbPath = argv[++i];
    else if (argv[i] === '-h' || argv[i] === '--help') {
      console.log(`Tracker restore CLI

Usage: tsx scripts/restore.ts [--db <db-path>] <backup-file.db.gz>

STOP the tracker server before running.

  --db <path>     Override target DB path (default: $DB_PATH or ./data/tracker.db)
`);
      process.exit(0);
    } else backupPath = argv[i];
  }
  if (!backupPath) {
    console.error('Backup file path required. Try --help.');
    process.exit(1);
  }
  return { backupPath, dbPath };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  console.log(`Restoring from ${args.backupPath} ...`);
  const r = restore({ backupPath: args.backupPath, dbPath: args.dbPath });
  if (r.integrity === 'ok') {
    console.log(`✓ Restored: ${r.restored_path} (${(r.bytes / 1024 / 1024).toFixed(2)} MB, integrity OK)`);
  } else {
    console.error(`✗ Restored ${r.restored_path} but integrity_check returned: ${r.integrity}`);
    process.exit(2);
  }
}

main().catch((e) => {
  console.error(`Restore failed: ${e.message}`);
  process.exit(1);
});
