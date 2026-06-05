/**
 * Tests for the three Real-Evidence-Only (REO) CI guardrails:
 *
 *   - scripts/lint-no-stubs.mjs
 *   - scripts/check-provenance.mjs
 *   - scripts/check-coverage-regression.mjs
 *
 * Each test writes a small fixture into a temp directory, invokes the script
 * with `--json` (so we can assert the structured result), and asserts on
 * exit code + reported hits/issues/regressions.
 *
 * These guardrails are the enforcement layer for the REO standard described
 * in `cloud-evidence/CLAUDE.md`. If any of these tests regress, the guardrails
 * stop reliably blocking stubs/missing-provenance/coverage-regression and the
 * REO contract is no longer enforceable.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const SCRIPTS = {
  lint: resolve(REPO_ROOT, 'scripts', 'lint-no-stubs.mjs'),
  provenance: resolve(REPO_ROOT, 'scripts', 'check-provenance.mjs'),
  coverage: resolve(REPO_ROOT, 'scripts', 'check-coverage-regression.mjs'),
};

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-reo-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function runNode(script: string, args: string[] = []) {
  const r = spawnSync('node', [script, ...args], { encoding: 'utf8' });
  return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

// ─── G1: lint:no-stubs ────────────────────────────────────────────────────────
describe('REO G1 — lint:no-stubs', () => {
  it('passes on a file with no forbidden tokens', () => {
    const d = tmp();
    const f = join(d, 'clean.ts');
    writeFileSync(f, 'export function add(a: number, b: number) { return a + b; }\n');
    const r = runNode(SCRIPTS.lint, ['--paths', f, '--json']);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.hits).toEqual([]);
  });

  it('flags TODO/FIXME/XXX markers', () => {
    const d = tmp();
    const f = join(d, 'dirty.ts');
    writeFileSync(f, [
      'export function f() {',
      '  // TODO: implement',
      '  return 1;',
      '}',
      '// FIXME later',
      '// XXX',
    ].join('\n'));
    const r = runNode(SCRIPTS.lint, ['--paths', f, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    const tokens = j.hits.map((h: { token: string }) => h.token).sort();
    expect(tokens).toEqual(['FIXME', 'TODO', 'XXX']);
  });

  it('flags placeholder / sample-data / fake-data / dummy-data', () => {
    const d = tmp();
    const f = join(d, 'fakes.ts');
    writeFileSync(f, [
      'export const x = "this is a placeholder value";',
      'const y = { evidence: "sample finding here" };',
      'const z = { sig: "fake signature" };',
      'const w = { uid: "dummy value" };',
    ].join('\n'));
    const r = runNode(SCRIPTS.lint, ['--paths', f, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    const tokens = j.hits.map((h: { token: string }) => h.token).sort();
    expect(tokens).toContain('placeholder');
    expect(tokens).toContain('sample-data');
    expect(tokens).toContain('fake-data');
    expect(tokens).toContain('dummy-data');
  });

  it('does NOT flag HTML/JSX placeholder="..." attributes (legitimate UI hint)', () => {
    const d = tmp();
    const f = join(d, 'jsx.tsx');
    writeFileSync(f, [
      'export default function Search() {',
      '  return <input type="text" placeholder="Search KSIs…" />;',
      '}',
    ].join('\n'));
    const r = runNode(SCRIPTS.lint, ['--paths', f, '--json']);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.hits).toEqual([]);
  });
});

// ─── G3: check:provenance ────────────────────────────────────────────────────
describe('REO G3 — check:provenance', () => {
  it('passes for a file with full provenance', () => {
    const d = tmp();
    const f = join(d, 'evidence.json');
    writeFileSync(f, JSON.stringify({
      provenance: {
        emitter: 'core/test-emitter.ts',
        emittedAt: '2026-06-05T00:00:00Z',
        sourceCalls: ['ec2.DescribeInstances'],
        signingKeyId: 'ed25519:abc123',
      },
      payload: { items: [] },
    }));
    const r = runNode(SCRIPTS.provenance, ['--dir', d, '--json']);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.issues).toEqual([]);
  });

  it('flags a file missing the top-level provenance block', () => {
    const d = tmp();
    writeFileSync(join(d, 'bad.json'), JSON.stringify({ payload: 'no provenance here' }));
    const r = runNode(SCRIPTS.provenance, ['--dir', d, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    expect(j.issues.length).toBeGreaterThan(0);
    expect(j.issues[0].issue).toMatch(/missing top-level `provenance`/);
  });

  it('flags a file with provenance but empty sourceCalls (no real evidence cited)', () => {
    const d = tmp();
    writeFileSync(join(d, 'empty-sources.json'), JSON.stringify({
      provenance: { emitter: 'x', emittedAt: 'now', sourceCalls: [], signingKeyId: 'k' },
    }));
    const r = runNode(SCRIPTS.provenance, ['--dir', d, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    expect(j.issues.some((i: { issue: string }) => /sourceCalls is empty/.test(i.issue))).toBe(true);
  });

  it('validates KSI envelope files structurally (ksi_id / run_id / collected_at / frmr_version / providers[].evidence[].source)', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify({
      ksi_id: 'KSI-IAM-MFA',
      run_id: 'r-1',
      collected_at: '2026-06-05T00:00:00Z',
      frmr_version: '0.9.43-beta',
      providers: [{ provider: 'aws', evidence: [{ source: 'iam.GetAccountSummary', data: { foo: 1 } }] }],
    }));
    const r = runNode(SCRIPTS.provenance, ['--dir', d, '--json']);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.issues).toEqual([]);
  });

  it('flags KSI envelope missing required fields', () => {
    const d = tmp();
    writeFileSync(join(d, 'KSI-IAM-MFA.json'), JSON.stringify({
      ksi_id: 'KSI-IAM-MFA',
      // run_id, collected_at, frmr_version, providers all missing
    }));
    const r = runNode(SCRIPTS.provenance, ['--dir', d, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    const issues = j.issues.map((i: { issue: string }) => i.issue);
    expect(issues.some((i: string) => /run_id/.test(i))).toBe(true);
    expect(issues.some((i: string) => /collected_at/.test(i))).toBe(true);
    expect(issues.some((i: string) => /frmr_version/.test(i))).toBe(true);
    expect(issues.some((i: string) => /providers/.test(i))).toBe(true);
  });

  it('exits 0 with a friendly message when the scan directory does not exist', () => {
    const r = runNode(SCRIPTS.provenance, ['--dir', '/tmp/this-dir-does-not-exist-cev-reo']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/nothing to verify/);
  });
});

// ─── G2: check:coverage-regression ───────────────────────────────────────────
describe('REO G2 — check:coverage-regression', () => {
  it('SKIPs (exit 0) when no current report exists', () => {
    const d = tmp();
    const r = runNode(SCRIPTS.coverage, ['--current', join(d, 'nope.json'), '--baseline', join(d, 'nope2.json')]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/SKIP/);
  });

  it('passes (exit 0) when current matches baseline', () => {
    const d = tmp();
    const cur = join(d, 'cur.json');
    const base = join(d, 'base.json');
    const report = {
      columns: [
        { column: 'DNS Name or URL', fillRate: { aws: 1.0, gcp: 0.5, azure: 0.0 } },
      ],
    };
    writeFileSync(cur, JSON.stringify(report));
    writeFileSync(base, JSON.stringify(report));
    const r = runNode(SCRIPTS.coverage, ['--current', cur, '--baseline', base, '--json']);
    expect(r.status).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.regressions).toEqual([]);
  });

  it('passes (exit 0) when current improves over baseline', () => {
    const d = tmp();
    const cur = join(d, 'cur.json');
    const base = join(d, 'base.json');
    writeFileSync(base, JSON.stringify({
      columns: [{ column: 'NetBIOS Name', fillRate: { aws: 0.5, gcp: 0.5, azure: 0.5 } }],
    }));
    writeFileSync(cur, JSON.stringify({
      columns: [{ column: 'NetBIOS Name', fillRate: { aws: 0.8, gcp: 0.5, azure: 0.5 } }],
    }));
    const r = runNode(SCRIPTS.coverage, ['--current', cur, '--baseline', base, '--json']);
    expect(r.status).toBe(0);
  });

  it('FAILs (exit 1) when current decreases vs baseline', () => {
    const d = tmp();
    const cur = join(d, 'cur.json');
    const base = join(d, 'base.json');
    writeFileSync(base, JSON.stringify({
      columns: [{ column: 'IPv4 or IPv6 Address', fillRate: { aws: 1.0, gcp: 1.0, azure: 1.0 } }],
    }));
    writeFileSync(cur, JSON.stringify({
      columns: [{ column: 'IPv4 or IPv6 Address', fillRate: { aws: 0.5, gcp: 1.0, azure: 1.0 } }],
    }));
    const r = runNode(SCRIPTS.coverage, ['--current', cur, '--baseline', base, '--json']);
    expect(r.status).toBe(1);
    const j = JSON.parse(r.stdout);
    expect(j.regressions).toHaveLength(1);
    expect(j.regressions[0].column).toBe('IPv4 or IPv6 Address');
    expect(j.regressions[0].cloud).toBe('aws');
  });

  it('passes (exit 0) when baseline file does not exist (first run)', () => {
    const d = tmp();
    const cur = join(d, 'cur.json');
    writeFileSync(cur, JSON.stringify({ columns: [] }));
    const r = runNode(SCRIPTS.coverage, ['--current', cur, '--baseline', join(d, 'no-baseline-yet.json')]);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/no baseline yet/);
  });
});
