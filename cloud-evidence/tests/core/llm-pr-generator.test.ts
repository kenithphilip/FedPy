/**
 * Tests for core/llm-pr-generator.ts.
 *
 * Uses the injectable `httpPost` to simulate the Anthropic API without making
 * network calls. Verifies happy path, error paths, and response parsing.
 */
import { describe, it, expect } from 'vitest';
import { generatePrForFinding, generatePrsForEvidence } from '../../core/llm-pr-generator.ts';
import type { Finding, EvidenceFile } from '../../core/envelope.ts';

function mkFinding(passed = false): Finding {
  return {
    rule: 'aws.iam.root_mfa_enabled',
    passed,
    severity: 'critical',
    current_state: { summary: 'Root MFA is off.', observations: { AccountMFAEnabled: 0 } },
    target_state: { summary: 'Root MFA enabled.', rationale: 'Root has unlimited blast radius.' },
    ...(passed ? {} : {
      gap: { description: 'Root MFA off.', affected_resources: [{ type: 'aws_account', identifier: '111122223333' }] },
      remediation: {
        summary: 'Enable root MFA.',
        options: [{ approach: 'Console: enable virtual MFA', mechanism: 'console', steps: ['Sign in as root', 'Enable MFA'] }],
      },
    }),
    nist_controls: ['IA-2', 'IA-2(1)'],
  };
}

function mkEvidence(finding: Finding): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'Multi-Factor Authentication',
    ksi_statement: 'MFA is enforced for every human user.',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'r1',
    collected_at: '2026-05-27T12:00:00Z',
    providers: [{
      provider: 'aws', account_id: '111122223333',
      evidence: [],
      findings: [finding],
    }],
    rollup: {
      pass: finding.passed,
      passing_findings: finding.passed ? 1 : 0,
      failing_findings: finding.passed ? 0 : 1,
      warnings: [], missing_evidence: [], alternatives_in_play: 0,
    },
  };
}

function fakeApiResponse(prObj: any): { status: number; body: string } {
  // Mirror the Anthropic Messages API shape
  return {
    status: 200,
    body: JSON.stringify({
      id: 'msg_test',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: JSON.stringify(prObj) }],
      stop_reason: 'end_turn',
      usage: { input_tokens: 100, output_tokens: 200 },
    }),
  };
}

const sampleLlmOutput = {
  title: 'Enable root MFA on AWS account',
  body_markdown: '## Summary\nThis change requires enabling MFA on the root user via the console. There is no Terraform-managed primitive for the root account.\n\n## Risks\n- Out-of-band setup required.',
  mechanism: 'process',
  files: [],
  risks: ['Root credential rotation must be coordinated with on-call.'],
  effort: 'minutes',
};

describe('generatePrForFinding', () => {
  it('returns the parsed PR on a happy-path API response', async () => {
    const r = await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
      apiKey: 'sk-test',
      httpPost: async () => fakeApiResponse(sampleLlmOutput),
    });
    expect(r.skipped).toBe(false);
    expect(r.pr?.title).toBe('Enable root MFA on AWS account');
    expect(r.pr?.mechanism).toBe('process');
    expect(r.pr?.risks?.length).toBeGreaterThan(0);
  });

  it('skips when ANTHROPIC_API_KEY is not set (and no override)', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const r = await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
    });
    expect(r.skipped).toBe(true);
    expect(r.reason).toMatch(/ANTHROPIC_API_KEY/);
  });

  it('reports skipped with reason on non-200 API response', async () => {
    const r = await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
      apiKey: 'sk-test',
      httpPost: async () => ({ status: 429, body: '{"error":"rate_limit"}' }),
    });
    expect(r.skipped).toBe(true);
    expect(r.reason).toMatch(/HTTP 429/);
  });

  it('reports skipped + raw_text when the LLM returns garbage', async () => {
    const r = await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
      apiKey: 'sk-test',
      httpPost: async () => ({
        status: 200,
        body: JSON.stringify({ content: [{ type: 'text', text: 'sorry, I cannot help' }] }),
      }),
    });
    expect(r.skipped).toBe(true);
    expect(r.raw_text).toBeTruthy();
  });

  it('parses LLM responses that include markdown code-fence wrappers', async () => {
    const wrapped = '```json\n' + JSON.stringify(sampleLlmOutput) + '\n```';
    const r = await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
      apiKey: 'sk-test',
      httpPost: async () => ({
        status: 200,
        body: JSON.stringify({ content: [{ type: 'text', text: wrapped }] }),
      }),
    });
    expect(r.skipped).toBe(false);
    expect(r.pr?.title).toBe('Enable root MFA on AWS account');
  });

  it('sends the expected headers and request body shape', async () => {
    let captured: { url?: string; headers?: any; body?: string } = {};
    await generatePrForFinding({
      finding: mkFinding(false),
      evidence: mkEvidence(mkFinding(false)),
      apiKey: 'sk-test-123',
      httpPost: async (url, headers, body) => {
        captured = { url, headers, body };
        return fakeApiResponse(sampleLlmOutput);
      },
    });
    expect(captured.url).toMatch(/anthropic\.com/);
    expect(captured.headers?.['x-api-key']).toBe('sk-test-123');
    expect(captured.headers?.['anthropic-version']).toBeTruthy();
    const parsedBody = JSON.parse(captured.body ?? '{}');
    expect(parsedBody.model).toBeTruthy();
    expect(parsedBody.messages?.[0]?.role).toBe('user');
    expect(parsedBody.system).toMatch(/JSON object/);
  });
});

describe('generatePrsForEvidence', () => {
  it('only attempts generation for failing findings', async () => {
    const failing = mkFinding(false);
    const passing = mkFinding(true);
    const ev = mkEvidence(failing);
    ev.providers[0].findings = [failing, passing];

    let calls = 0;
    const r = await generatePrsForEvidence(ev, {
      apiKey: 'sk-test',
      httpPost: async () => { calls++; return fakeApiResponse(sampleLlmOutput); },
    });
    expect(calls).toBe(1);
    expect(r).toHaveLength(1);
    expect(r[0].rule).toBe(failing.rule);
  });
});
