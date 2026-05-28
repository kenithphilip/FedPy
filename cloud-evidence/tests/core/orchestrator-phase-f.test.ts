/**
 * Orchestrator-level integration test for Phase F wiring.
 *
 * Verifies that when the user passes `--llm-generate-prs`, `--ticket-push`,
 * `--siem-url`, and `--webhook-url`, all four integrations actually fire with
 * the right shape of inputs.
 *
 * Strategy:
 *   1. Mock `core/auth/aws.ts` with the fake-aws-sdk used by other tests, so
 *      collectors run without real AWS creds and produce a deterministic
 *      providerBlock with a failing finding.
 *   2. Mock `core/auth/gcp.ts` so GCP auth doesn't fail; GCP is disabled in
 *      the test config so this is belt-and-suspenders.
 *   3. Mock the four Phase F integration modules so their network-side
 *      effects don't actually hit the network. Each mock records the calls
 *      it received so the test can assert on them.
 *   4. Build a minimal `config.yaml` + run `main()`.
 *   5. Assert each mock was called with the expected shape AND that the
 *      summary log files were written.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { setFakeResponses } from '../helpers/fake-aws-sdk.ts';

// ---- Module mocks ----

// AWS auth → fake-aws-sdk
vi.mock('../../core/auth/aws.ts', () => import('../helpers/fake-aws-sdk.ts'));

// GCP auth → stub
vi.mock('../../core/auth/gcp.ts', () => ({
  whoAmIGcp: async () => ({ principal: 'test@example.com' }),
  googleClient: async () => ({}),
  guardGcp: (x: any) => x,
}));

// Phase F integrations — record every call
const llmCalls: any[] = [];
const ticketDriverCalls: any[] = [];
const ticketPushCalls: any[] = [];
const siemCalls: any[] = [];
const webhookRunSummaryCalls: any[] = [];
const webhookFindingCalls: any[] = [];

vi.mock('../../core/llm-pr-generator.ts', () => ({
  generatePrsForEvidence: vi.fn(async (ev: any) => {
    llmCalls.push({ ksi: ev.ksi_id });
    return [{
      rule: 'aws.iam.test_rule',
      result: {
        skipped: false,
        pr: { title: 'Fix MFA', body_markdown: 'x', mechanism: 'terraform', files: [], risks: [], effort: 'hours' },
      },
    }];
  }),
}));

vi.mock('../../core/ticket-push.ts', () => ({
  pushFailingFindings: vi.fn(async (_driver: any, ev: any) => {
    ticketPushCalls.push({ ksi: ev.ksi_id });
    return { provider: 'github', pushed: [{ external_key: 'k', ticket_id: '1', url: 'https://x', status: 'opened' }], errors: [] };
  }),
  gitHubIssuesDriver: vi.fn((opts: any) => {
    ticketDriverCalls.push({ name: 'github', opts });
    return { name: 'github', push: vi.fn() };
  }),
  jiraDriver: vi.fn((opts: any) => {
    ticketDriverCalls.push({ name: 'jira', opts });
    return { name: 'jira', push: vi.fn() };
  }),
  serviceNowDriver: vi.fn((opts: any) => {
    ticketDriverCalls.push({ name: 'servicenow', opts });
    return { name: 'servicenow', push: vi.fn() };
  }),
}));

vi.mock('../../core/siem-push.ts', () => ({
  pushEvidenceToSiem: vi.fn(async (ev: any, opts: any) => {
    siemCalls.push({ ksi: ev.ksi_id, url: opts.url, format: opts.format });
    return { batches_sent: 1, events_sent: 2, failures: [] };
  }),
}));

vi.mock('../../core/webhook-push.ts', () => ({
  sendRunSummary: vi.fn(async (opts: any, body: any) => {
    webhookRunSummaryCalls.push({ url: opts.url, body });
    return { url: opts.url, ok: true, status: 200 };
  }),
  sendFailingFindings: vi.fn(async (opts: any, ev: any) => {
    webhookFindingCalls.push({ url: opts.url, ksi: ev.ksi_id });
    return [{ url: opts.url, ok: true, status: 200 }];
  }),
}));

// Stub the actual IAM collector to return a deterministic failing finding,
// so we don't depend on real SDK behavior or fixture branching.
vi.mock('../../providers/aws/iam.ts', async () => {
  return {
    collectIamMfa: async (ctx: any) => ({
      provider: 'aws',
      account_id: ctx.aws?.account_id ?? '111122223333',
      region_set: ['us-east-1'],
      evidence: [],
      findings: [
        {
          rule: 'aws.iam.root_mfa_enabled',
          passed: false,
          severity: 'critical',
          current_state: { summary: 'Root MFA off.', observations: { AccountMFAEnabled: 0 } },
          target_state: { summary: 'Root MFA on.', rationale: 'Root has unlimited blast radius.' },
          gap: { description: 'Root MFA off.', affected_resources: [{ type: 'aws_account', identifier: '111122223333' }] },
          remediation: {
            summary: 'Enable root MFA.',
            options: [{ approach: 'Console: enable MFA', mechanism: 'console', steps: ['Sign in', 'Enable'] }],
          },
        },
      ],
    }),
    // Other collectors in this module aren't called when --ksis=KSI-IAM-MFA
    collectIamAam: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectIamApm: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectIamElp: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectIamJit: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectIamSnu: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectIamSus: async () => ({ provider: 'aws', evidence: [], findings: [] }),
    collectCnaDfp: async () => ({ provider: 'aws', evidence: [], findings: [] }),
  };
});

// ---- Test setup ----

let tmp: string;
let originalArgv: string[];
let originalEnv: NodeJS.ProcessEnv;

function makeConfig(tmpDir: string): string {
  const configPath = resolve(tmpDir, 'config.yaml');
  writeFileSync(configPath, `
frmr_version: "test-1.0"
aws:
  enabled: true
  regions: ["us-east-1"]
gcp:
  enabled: false
  organization_id: null
  projects: []
output_dir: "${resolve(tmpDir, 'out')}"
`);
  return configPath;
}

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), 'cev-orch-f-'));
  llmCalls.length = 0;
  ticketDriverCalls.length = 0;
  ticketPushCalls.length = 0;
  siemCalls.length = 0;
  webhookRunSummaryCalls.length = 0;
  webhookFindingCalls.length = 0;
  setFakeResponses({});
  originalArgv = process.argv;
  originalEnv = { ...process.env };
});

afterEach(() => {
  process.argv = originalArgv;
  process.env = originalEnv;
  rmSync(tmp, { recursive: true, force: true });
});

describe('orchestrator → Phase F integration wiring', () => {
  it('fires all four integrations when their flags + env are set', async () => {
    const configPath = makeConfig(tmp);
    const outDir = resolve(tmp, 'out');

    process.argv = [
      'node', 'orchestrator.ts',
      '--config', configPath,
      '--out', outDir,
      '--providers', 'aws',
      '--ksis', 'KSI-IAM-MFA',
      '--no-sign',                                  // skip Ed25519 + key generation
      '--llm-generate-prs',
      '--ticket-push', 'github',
      '--siem-url', 'https://siem.example/intake',
      '--webhook-url', 'https://hook.example/in',
    ];
    process.env.ANTHROPIC_API_KEY = 'sk-test';
    process.env.GITHUB_TOKEN = 'gh-test';
    process.env.GITHUB_REPO = 'org/repo';
    process.env.CLOUD_EVIDENCE_WEBHOOK_SECRET = 'shh';
    delete process.env.CLOUD_EVIDENCE_NO_TSA;
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';        // skip openssl shellout

    const { main } = await import('../../core/orchestrator.ts');
    await main();

    // 1. LLM PR generator was called once per evidence file (here, 1 KSI)
    expect(llmCalls).toHaveLength(1);
    expect(llmCalls[0].ksi).toBe('KSI-IAM-MFA');
    expect(existsSync(resolve(outDir, 'llm-prs.json'))).toBe(true);
    const llmReport = JSON.parse(readFileSync(resolve(outDir, 'llm-prs.json'), 'utf8'));
    expect(llmReport[0].pr_title).toBe('Fix MFA');

    // 2. Ticket driver built once (github), ticket push called per evidence file
    expect(ticketDriverCalls).toHaveLength(1);
    expect(ticketDriverCalls[0].name).toBe('github');
    expect(ticketDriverCalls[0].opts).toMatchObject({ token: 'gh-test', repo: 'org/repo' });
    expect(ticketPushCalls).toHaveLength(1);

    // 3. SIEM push called per evidence file
    expect(siemCalls).toHaveLength(1);
    expect(siemCalls[0].url).toBe('https://siem.example/intake');
    expect(siemCalls[0].format).toBe('ocsf-jsonl');

    // 4. Webhook run-summary sent once (always); per-finding off by default
    expect(webhookRunSummaryCalls).toHaveLength(1);
    expect(webhookRunSummaryCalls[0].url).toBe('https://hook.example/in');
    expect(webhookRunSummaryCalls[0].body.run_id).toBeTruthy();
    expect(webhookFindingCalls).toHaveLength(0);

    // Sanity: evidence file was emitted
    expect(existsSync(resolve(outDir, 'KSI-IAM-MFA.json'))).toBe(true);
  });

  it('--ticket-push jira selects the jira driver with the right env vars', async () => {
    const configPath = makeConfig(tmp);
    const outDir = resolve(tmp, 'out');

    process.argv = [
      'node', 'orchestrator.ts',
      '--config', configPath,
      '--out', outDir,
      '--providers', 'aws',
      '--ksis', 'KSI-IAM-MFA',
      '--no-sign',
      '--ticket-push', 'jira',
    ];
    process.env.JIRA_SITE_URL = 'https://acme.atlassian.net';
    process.env.JIRA_EMAIL = 'a@b.com';
    process.env.JIRA_API_TOKEN = 'token';
    process.env.JIRA_PROJECT_KEY = 'SEC';
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';

    const { main } = await import('../../core/orchestrator.ts');
    await main();

    expect(ticketDriverCalls.some((c) => c.name === 'jira')).toBe(true);
    const jira = ticketDriverCalls.find((c) => c.name === 'jira')!;
    expect(jira.opts).toMatchObject({ siteUrl: 'https://acme.atlassian.net', projectKey: 'SEC' });
  });

  it('aborts BEFORE collection when --llm-generate-prs is set but ANTHROPIC_API_KEY is missing', async () => {
    // Post-2026-05-audit behavior: missing env vars for opted-in integrations
    // are caught at startup so we don't waste compute on a doomed run.
    const configPath = makeConfig(tmp);
    const outDir = resolve(tmp, 'out');

    process.argv = [
      'node', 'orchestrator.ts',
      '--config', configPath,
      '--out', outDir,
      '--providers', 'aws',
      '--ksis', 'KSI-IAM-MFA',
      '--no-sign',
      '--llm-generate-prs',
    ];
    delete process.env.ANTHROPIC_API_KEY;
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';

    const consoleErr = vi.spyOn(console, 'error').mockImplementation(() => {});
    // Intercept process.exit so the test runner doesn't terminate.
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`__exit_${code ?? 0}__`);
    }) as any);

    const { main } = await import('../../core/orchestrator.ts');
    await expect(main()).rejects.toThrow(/__exit_1__/);

    // Collection never ran, LLM never invoked.
    expect(llmCalls).toHaveLength(0);
    // Operator saw an actionable message naming the missing env var.
    const allErrs = consoleErr.mock.calls.map((c) => String(c[0])).join('\n');
    expect(allErrs).toMatch(/ANTHROPIC_API_KEY/);
    expect(allErrs).toMatch(/--llm-generate-prs/);

    consoleErr.mockRestore();
    exitSpy.mockRestore();
  });

  it('does NOT fire integrations when their flags are absent', async () => {
    const configPath = makeConfig(tmp);
    const outDir = resolve(tmp, 'out');

    process.argv = [
      'node', 'orchestrator.ts',
      '--config', configPath,
      '--out', outDir,
      '--providers', 'aws',
      '--ksis', 'KSI-IAM-MFA',
      '--no-sign',
    ];
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';

    const { main } = await import('../../core/orchestrator.ts');
    await main();

    expect(llmCalls).toHaveLength(0);
    expect(ticketPushCalls).toHaveLength(0);
    expect(siemCalls).toHaveLength(0);
    expect(webhookRunSummaryCalls).toHaveLength(0);
  });

  it('sends per-finding webhook events when CLOUD_EVIDENCE_WEBHOOK_PER_FINDING=1', async () => {
    const configPath = makeConfig(tmp);
    const outDir = resolve(tmp, 'out');

    process.argv = [
      'node', 'orchestrator.ts',
      '--config', configPath,
      '--out', outDir,
      '--providers', 'aws',
      '--ksis', 'KSI-IAM-MFA',
      '--no-sign',
      '--webhook-url', 'https://hook.example/in',
    ];
    process.env.CLOUD_EVIDENCE_WEBHOOK_SECRET = 'shh';
    process.env.CLOUD_EVIDENCE_WEBHOOK_PER_FINDING = '1';
    process.env.CLOUD_EVIDENCE_NO_TSA = '1';

    const { main } = await import('../../core/orchestrator.ts');
    await main();

    expect(webhookRunSummaryCalls).toHaveLength(1);
    expect(webhookFindingCalls.length).toBeGreaterThanOrEqual(1);
    expect(webhookFindingCalls[0].ksi).toBe('KSI-IAM-MFA');
  });
});
