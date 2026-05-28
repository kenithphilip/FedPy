/**
 * Tracker backup CLI.
 *
 * Usage:
 *   tsx scripts/backup.ts                          # writes to ./backups/
 *   tsx scripts/backup.ts --dir /var/backups/...   # custom directory
 *   tsx scripts/backup.ts --retention 30           # also prune backups older than N days
 */
import { resolve } from 'node:path';
import { backup, pruneBackups, listBackups } from '../server/backup.ts';

function parseArgs(argv: string[]): { dir: string; retentionDays: number | null; list: boolean } {
  let dir = resolve(process.cwd(), 'backups');
  let retentionDays: number | null = null;
  let list = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') dir = resolve(argv[++i] ?? dir);
    else if (a === '--retention') retentionDays = Number(argv[++i] ?? '0');
    else if (a === '--list') list = true;
    else if (a === '-h' || a === '--help') {
      console.log(`Tracker backup CLI

Usage: tsx scripts/backup.ts [options]

  --dir <path>          Backup directory (default: ./backups)
  --retention <days>    Delete backups older than N days
  --list                List existing backups instead of creating a new one
`);
      process.exit(0);
    }
  }
  return { dir, retentionDays, list };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.list) {
    const entries = listBackups(args.dir);
    if (entries.length === 0) {
      console.log(`No backups in ${args.dir}`);
      return;
    }
    console.log(`Backups in ${args.dir}:`);
    for (const e of entries) {
      const mb = (e.bytes / 1024 / 1024).toFixed(2);
      console.log(`  ${e.name}  ${mb}MB  ${e.modified_at}`);
    }
    return;
  }

  const r = await backup(args.dir);
  const ratio = ((1 - r.bytes_compressed / r.bytes_uncompressed) * 100).toFixed(1);
  console.log(`✓ Backup: ${r.path}`);
  console.log(`  ${(r.bytes_uncompressed / 1024 / 1024).toFixed(2)} MB → ${(r.bytes_compressed / 1024 / 1024).toFixed(2)} MB (gzip saved ${ratio}%)`);

  if (args.retentionDays && args.retentionDays > 0) {
    const removed = pruneBackups(args.dir, args.retentionDays);
    if (removed > 0) console.log(`  pruned ${removed} backup(s) older than ${args.retentionDays} days`);
  }
}

main().catch((e) => {
  console.error(`Backup failed: ${e.message}`);
  process.exit(1);
});
