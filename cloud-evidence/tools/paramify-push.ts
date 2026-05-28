/**
 * paramify-push — adapter that posts cloud-evidence findings into Paramify.
 *
 * Reads every KSI-*.json file from the evidence output directory and POSTs
 * each one into Paramify via its REST API. Idempotent on (ksi_id, run_id).
 *
 * Auth: PARAMIFY_API_TOKEN env var (Bearer)
 * Base URL: PARAMIFY_BASE_URL env var (e.g. https://api.paramify.com)
 *
 * Usage:
 *   PARAMIFY_API_TOKEN=... PARAMIFY_BASE_URL=https://api.paramify.com \
 *     npx tsx tools/paramify-push.ts --out ./out [--dry-run]
 *
 * Note: Paramify's KSI-evidence ingestion API surface is product-specific.
 * The mapping in this adapter follows a generic shape — adjust `mapToParamify`
 * to match your Paramify tenant's actual endpoint + body schema.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type { EvidenceFile } from '../core/envelope.ts';

interface Args {
  outDir: string;
  dryRun: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { outDir: resolve(process.cwd(), 'out'), dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') args.outDir = resolve(argv[++i] ?? './out');
    else if (argv[i] === '--dry-run') args.dryRun = true;
    else if (argv[i] === '-h' || argv[i] === '--help') {
      console.log('Usage: paramify-push --out <dir> [--dry-run]');
      process.exit(0);
    }
  }
  return args;
}

interface ParamifyEvidencePayload {
  ksi_id: string;
  ksi_name: string;
  run_id: string;
  collected_at: string;
  status: 'met' | 'in_progress' | 'not_started' | 'blocked';
  finding_summary: string;
  failing_finding_rules: string[];
  passing_finding_rules: string[];
  alternative_satisfiers: Array<{ via: string; detected: boolean }>;
  evidence_payload: EvidenceFile;
}

function statusFromRollup(file: EvidenceFile): ParamifyEvidencePayload['status'] {
  if (file.rollup.pass) return 'met';
  // Heuristic: if any critical or high failing, mark in_progress; otherwise still met
  const hasFailing = file.providers.some((p) =>
    p.findings.some((f) => !f.passed && (f.severity === 'critical' || f.severity === 'high'))
  );
  return hasFailing ? 'in_progress' : 'met';
}

function mapToParamify(file: EvidenceFile): ParamifyEvidencePayload {
  const failingRules: string[] = [];
  const passingRules: string[] = [];
  for (const p of file.providers) {
    for (const f of p.findings) {
      if (f.passed) passingRules.push(`${p.provider}:${f.rule}`);
      else failingRules.push(`${p.provider}:${f.rule}(${f.severity})`);
    }
  }
  const altSatisfiers = file.providers.flatMap((p) =>
    (p.ksi_level_alternatives ?? []).map((a) => ({ via: a.via, detected: a.detected }))
  );

  return {
    ksi_id: file.ksi_id,
    ksi_name: file.ksi_name,
    run_id: file.run_id,
    collected_at: file.collected_at,
    status: statusFromRollup(file),
    finding_summary: file.summary_for_llm ?? '(no summary)',
    failing_finding_rules: failingRules,
    passing_finding_rules: passingRules,
    alternative_satisfiers: altSatisfiers,
    evidence_payload: file,
  };
}

async function pushOne(baseUrl: string, token: string, payload: ParamifyEvidencePayload, dryRun: boolean): Promise<{ ok: boolean; status?: number; error?: string }> {
  if (dryRun) {
    console.log(`  [DRY-RUN] would POST ${payload.ksi_id} status=${payload.status} failing=${payload.failing_finding_rules.length}`);
    return { ok: true };
  }
  try {
    const url = `${baseUrl.replace(/\/$/, '')}/v1/ksi-evidence`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      return { ok: false, status: res.status, error: txt.slice(0, 500) };
    }
    return { ok: true, status: res.status };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const token = process.env.PARAMIFY_API_TOKEN;
  const baseUrl = process.env.PARAMIFY_BASE_URL;

  if (!args.dryRun) {
    if (!token) { console.error('PARAMIFY_API_TOKEN not set'); process.exit(1); }
    if (!baseUrl) { console.error('PARAMIFY_BASE_URL not set'); process.exit(1); }
  }

  const files = readdirSync(args.outDir).filter((f) => f.startsWith('KSI-') && f.endsWith('.json') && !f.includes('.example.'));
  console.log(`Paramify push: ${files.length} evidence file(s)${args.dryRun ? ' (DRY RUN)' : ''}`);

  let ok = 0;
  let fail = 0;
  for (const f of files) {
    const file = JSON.parse(readFileSync(resolve(args.outDir, f), 'utf8')) as EvidenceFile;
    const payload = mapToParamify(file);
    const result = await pushOne(baseUrl ?? '', token ?? '', payload, args.dryRun);
    if (result.ok) {
      ok++;
      if (!args.dryRun) console.log(`  ✓ ${file.ksi_id} (HTTP ${result.status})`);
    } else {
      fail++;
      console.error(`  ✗ ${file.ksi_id} → ${result.status ?? ''} ${result.error ?? ''}`);
    }
  }
  console.log(`\nPushed: ${ok}/${files.length}; failed: ${fail}`);
  if (fail > 0) process.exitCode = 1;
}

main().catch((e) => { console.error('Fatal:', e); process.exit(1); });
