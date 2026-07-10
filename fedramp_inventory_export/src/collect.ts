/**
 * Optional `--collect` seam: drive FedPy's read-only collector to (re)produce a
 * fresh `out/` before the offline transform runs.
 *
 * This shells out to the cloud-evidence collector exactly as an operator would
 * (`npm run collect -- --inventory-workbook --impact-level moderate ...`), so the
 * read-only guardrails, signing, and evidence envelopes are produced by FedPy
 * itself — this tool never touches a cloud SDK. It just runs the collector as a
 * subprocess and then reads the artifacts it wrote.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

export interface CollectOptions {
  /** cloud-evidence project dir (holds package.json with the `collect` script). */
  collectorDir: string;
  /** Where the collector should write its run (its --out-dir). */
  outDir: string;
  /** Providers to sweep (default: whatever config.yaml enables). */
  providers?: string[];
  /** Extra raw args appended to the collect invocation. */
  extraArgs?: string[];
}

/**
 * Run the collector. Evaluates at Moderate, benchmarks BOTH framings by running
 * once per framework isn't needed — the benchmark is rebuilt offline here for
 * both — so we only need the collector to emit inventory + per-requirement
 * evidence. Resolves when the subprocess exits 0; rejects otherwise.
 */
export function runCollector(opts: CollectOptions): Promise<void> {
  const pkg = resolve(opts.collectorDir, 'package.json');
  if (!existsSync(pkg)) {
    return Promise.reject(
      new Error(`No package.json in collector dir ${opts.collectorDir}. Pass --collector-dir <path-to-cloud-evidence>.`),
    );
  }
  const args = [
    'run', 'collect', '--',
    '--inventory-workbook',
    '--impact-level', 'moderate',
    '--out-dir', resolve(opts.outDir),
  ];
  if (opts.providers?.length) args.push('--providers', opts.providers.join(','));
  if (opts.extraArgs?.length) args.push(...opts.extraArgs);

  return new Promise((resolvePromise, reject) => {
    const child = spawn('npm', args, {
      cwd: opts.collectorDir,
      stdio: 'inherit',
      env: process.env,
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`Collector exited with code ${code}. See its output above.`));
    });
  });
}
