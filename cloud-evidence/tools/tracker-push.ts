/**
 * tracker-push — opt-in adapter that PATCHes per-KSI state into the local tracker.
 *
 * The tracker exposes:
 *   PATCH /api/items/indicator/{ksi_id}
 *   body: { status, owner_text?, notes?, evidence_url?, last_reviewed? }
 *
 * This adapter logs into the tracker with a service account, then walks every
 * KSI-*.json in the evidence directory and PATCHes the matching indicator with:
 *   - status: derived from rollup.pass + finding severities
 *   - notes: summary_for_llm + run_id + failing-rule list
 *   - evidence_url: file:// URL of the evidence JSON
 *   - last_reviewed: today (UTC date)
 *
 * Usage:
 *   TRACKER_BASE_URL=http://localhost:4000 TRACKER_EMAIL=svc@... TRACKER_PASSWORD=... \
 *     npx tsx tools/tracker-push.ts --out ./out [--dry-run]
 */
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile } from '../core/envelope.ts';

interface Args { outDir: string; dryRun: boolean; }
function parseArgs(argv: string[]): Args {
  const args: Args = { outDir: resolve(process.cwd(), 'out'), dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') args.outDir = resolve(argv[++i] ?? './out');
    else if (argv[i] === '--dry-run') args.dryRun = true;
    else if (argv[i] === '-h' || argv[i] === '--help') {
      console.log('Usage: tracker-push --out <dir> [--dry-run]');
      process.exit(0);
    }
  }
  return args;
}

function statusFromFile(file: EvidenceFile): 'met' | 'in_progress' | 'blocked' | 'not_applicable' {
  if (file.rollup.pass) return 'met';
  const hasCritical = file.providers.some((p) => p.findings.some((f) => !f.passed && f.severity === 'critical'));
  if (hasCritical) return 'blocked';
  return 'in_progress';
}

function buildNotes(file: EvidenceFile): string {
  const failing: string[] = [];
  for (const p of file.providers) {
    for (const f of p.findings) {
      if (!f.passed) failing.push(`${p.provider}:${f.rule}(${f.severity})`);
    }
  }
  const head = file.summary_for_llm ?? `Run ${file.run_id}`;
  const tail = failing.length ? `\n\nFailing rules: ${failing.join('; ')}` : '';
  return head + tail;
}

async function login(baseUrl: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error(`Login failed: ${res.status}`);
  // Extract session cookie
  const setCookie = res.headers.get('set-cookie') ?? '';
  const m = setCookie.match(/fr20x_sid=([^;]+)/);
  if (!m) throw new Error('No session cookie in login response');
  return m[1]!;
}

async function patchItem(baseUrl: string, cookie: string, ksiId: string, body: any, dryRun: boolean): Promise<{ ok: boolean; status?: number; error?: string }> {
  if (dryRun) {
    console.log(`  [DRY-RUN] PATCH ${ksiId} status=${body.status}`);
    return { ok: true };
  }
  try {
    const res = await fetch(`${baseUrl}/api/items/indicator/${encodeURIComponent(ksiId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', 'Cookie': `fr20x_sid=${cookie}` },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      return { ok: false, status: res.status, error: txt.slice(0, 300) };
    }
    return { ok: true, status: res.status };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const baseUrl = process.env.TRACKER_BASE_URL;
  const email = process.env.TRACKER_EMAIL;
  const password = process.env.TRACKER_PASSWORD;

  if (!args.dryRun) {
    if (!baseUrl) { console.error('TRACKER_BASE_URL not set'); process.exit(1); }
    if (!email || !password) { console.error('TRACKER_EMAIL / TRACKER_PASSWORD not set'); process.exit(1); }
  }

  let cookie = '';
  if (!args.dryRun) {
    cookie = await login(baseUrl!, email!, password!);
    console.log(`Authenticated to ${baseUrl}`);
  }

  const files = readdirSync(args.outDir).filter((f) => f.startsWith('KSI-') && f.endsWith('.json') && !f.includes('.example.'));
  console.log(`Tracker push: ${files.length} evidence file(s)${args.dryRun ? ' (DRY RUN)' : ''}`);

  let ok = 0;
  let fail = 0;
  const today = new Date().toISOString().slice(0, 10);
  for (const f of files) {
    const filePath = resolve(args.outDir, f);
    const file = JSON.parse(readFileSync(filePath, 'utf8')) as EvidenceFile;
    const body = {
      status: statusFromFile(file),
      notes: buildNotes(file),
      evidence_url: `file://${filePath}`,
      last_reviewed: today,
    };
    const result = await patchItem(baseUrl ?? '', cookie, file.ksi_id, body, args.dryRun);
    if (result.ok) {
      ok++;
      if (!args.dryRun) console.log(`  ✓ ${file.ksi_id} ← ${body.status}`);
    } else {
      fail++;
      console.error(`  ✗ ${file.ksi_id} → ${result.status ?? ''} ${result.error ?? ''}`);
    }
  }
  console.log(`\nPushed: ${ok}/${files.length}; failed: ${fail}`);
  if (fail > 0) process.exitCode = 1;
}

main().catch((e) => { console.error('Fatal:', e); process.exit(1); });
