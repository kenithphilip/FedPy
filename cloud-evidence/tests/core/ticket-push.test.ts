/**
 * Tests for core/ticket-push.ts — driver-level idempotency + create/update/reopen flows.
 *
 * Uses the injectable `http` function to simulate the GitHub/Jira/ServiceNow APIs.
 */
import { describe, it, expect } from 'vitest';
import {
  gitHubIssuesDriver, jiraDriver, serviceNowDriver,
  pushFailingFindings, buildExternalKey,
  type HttpFn,
} from '../../core/ticket-push.ts';
import type { Finding, EvidenceFile } from '../../core/envelope.ts';

function mkFinding(rule: string, passed: boolean): Finding {
  return {
    rule, passed, severity: passed ? 'info' : 'high',
    current_state: { summary: 'x', observations: null },
    target_state: { summary: 'x', rationale: 'x' },
    ...(passed ? {} : {
      gap: { description: 'x', affected_resources: [{ type: 't', identifier: 'i' }] },
      remediation: { summary: 'x', options: [{ approach: 'a', mechanism: 'cli', steps: ['s'] }] },
    }),
  };
}

function mkEvidence(findings: Finding[]): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'Multi-Factor Authentication',
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'r',
    collected_at: '2026-05-27T12:00:00Z',
    providers: [{ provider: 'aws', account_id: '111122223333', evidence: [], findings }],
    rollup: { pass: findings.every((f) => f.passed), passing_findings: 0, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

describe('buildExternalKey', () => {
  it('produces a stable key', () => {
    const f = mkFinding('rule-1', false);
    const ev = mkEvidence([f]);
    const k1 = buildExternalKey(f, ev, 'aws', '111122223333');
    const k2 = buildExternalKey(f, ev, 'aws', '111122223333');
    expect(k1).toBe(k2);
    expect(k1).toContain('KSI-IAM-MFA');
    expect(k1).toContain('rule-1');
  });
});

describe('gitHubIssuesDriver', () => {
  it('creates an issue when search returns nothing', async () => {
    const calls: Array<{ method: string; url: string; body?: string }> = [];
    const http: HttpFn = async (method, url, _headers, body) => {
      calls.push({ method, url, body: body ?? undefined });
      if (url.includes('/search/issues')) return { status: 200, body: JSON.stringify({ items: [] }), headers: {} };
      if (url.endsWith('/issues')) return { status: 201, body: JSON.stringify({ number: 42, html_url: 'https://github.com/o/r/issues/42' }), headers: {} };
      return { status: 404, body: '', headers: {} };
    };
    const driver = gitHubIssuesDriver({ token: 'gh_test', repo: 'o/r', http });
    const r = await driver.push({
      externalKey: 'KSI-IAM-MFA|rule|aws|111',
      finding: mkFinding('rule', false),
      evidence: mkEvidence([mkFinding('rule', false)]),
    });
    expect(r.status).toBe('opened');
    expect(r.ticket_id).toBe('42');
    expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/issues'))).toBe(true);
  });

  it('updates an existing open issue with a comment', async () => {
    const calls: Array<{ method: string; url: string }> = [];
    const http: HttpFn = async (method, url) => {
      calls.push({ method, url });
      if (url.includes('/search/issues')) {
        return { status: 200, body: JSON.stringify({ items: [{ number: 7, html_url: 'https://github.com/o/r/issues/7', state: 'open' }] }), headers: {} };
      }
      return { status: 201, body: '{}', headers: {} };
    };
    const driver = gitHubIssuesDriver({ token: 'gh_test', repo: 'o/r', http });
    const r = await driver.push({
      externalKey: 'KSI-IAM-MFA|rule|aws|111',
      finding: mkFinding('rule', false),
      evidence: mkEvidence([mkFinding('rule', false)]),
    });
    expect(r.status).toBe('updated');
    expect(r.ticket_id).toBe('7');
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('/comments'))).toBe(true);
  });

  it('reopens a closed issue + comments on re-failure', async () => {
    const calls: Array<{ method: string; url: string; body?: string }> = [];
    const http: HttpFn = async (method, url, _h, body) => {
      calls.push({ method, url, body: body ?? undefined });
      if (url.includes('/search/issues')) {
        return { status: 200, body: JSON.stringify({ items: [{ number: 7, html_url: 'https://github.com/o/r/issues/7', state: 'closed' }] }), headers: {} };
      }
      return { status: 200, body: '{}', headers: {} };
    };
    const driver = gitHubIssuesDriver({ token: 'gh_test', repo: 'o/r', http });
    const r = await driver.push({
      externalKey: 'KSI-IAM-MFA|rule|aws|111',
      finding: mkFinding('rule', false),
      evidence: mkEvidence([mkFinding('rule', false)]),
    });
    expect(r.status).toBe('reopened');
    const patch = calls.find((c) => c.method === 'PATCH' && c.url.includes('/issues/7'));
    expect(patch).toBeTruthy();
    expect(patch?.body).toContain('"state":"open"');
  });
});

describe('jiraDriver', () => {
  it('creates a new issue when JQL search returns nothing', async () => {
    const http: HttpFn = async (method, url) => {
      if (method === 'GET' && url.includes('/rest/api/3/search')) {
        return { status: 200, body: JSON.stringify({ issues: [] }), headers: {} };
      }
      if (method === 'POST' && url.endsWith('/rest/api/3/issue')) {
        return { status: 201, body: JSON.stringify({ key: 'SEC-100' }), headers: {} };
      }
      return { status: 404, body: '', headers: {} };
    };
    const driver = jiraDriver({ siteUrl: 'https://acme.atlassian.net', email: 'a@b', apiToken: 't', projectKey: 'SEC', http });
    const r = await driver.push({
      externalKey: 'KSI-IAM-MFA|rule|aws|111',
      finding: mkFinding('rule', false),
      evidence: mkEvidence([mkFinding('rule', false)]),
    });
    expect(r.status).toBe('opened');
    expect(r.ticket_id).toBe('SEC-100');
    expect(r.url).toContain('SEC-100');
  });
});

describe('serviceNowDriver', () => {
  it('creates an incident when search returns nothing', async () => {
    const http: HttpFn = async (method, url) => {
      if (method === 'GET' && url.includes('/api/now/table/incident')) {
        return { status: 200, body: JSON.stringify({ result: [] }), headers: {} };
      }
      if (method === 'POST' && url.endsWith('/api/now/table/incident')) {
        return { status: 201, body: JSON.stringify({ result: { sys_id: 'abc123' } }), headers: {} };
      }
      return { status: 404, body: '', headers: {} };
    };
    const driver = serviceNowDriver({ instanceUrl: 'https://acme.service-now.com', user: 'u', password: 'p', http });
    const r = await driver.push({
      externalKey: 'KSI-IAM-MFA|rule|aws|111',
      finding: mkFinding('rule', false),
      evidence: mkEvidence([mkFinding('rule', false)]),
    });
    expect(r.status).toBe('opened');
    expect(r.ticket_id).toBe('abc123');
  });
});

describe('pushFailingFindings', () => {
  it('only attempts push for failing findings; collects errors per finding', async () => {
    let calls = 0;
    const http: HttpFn = async (_method, url) => {
      calls++;
      if (url.includes('/search/issues')) return { status: 200, body: JSON.stringify({ items: [] }), headers: {} };
      // Simulate failure on issue create
      return { status: 500, body: '{"message":"oops"}', headers: {} };
    };
    const driver = gitHubIssuesDriver({ token: 'gh_test', repo: 'o/r', http });
    const ev = mkEvidence([mkFinding('rule-a', false), mkFinding('rule-b', true), mkFinding('rule-c', false)]);
    const r = await pushFailingFindings(driver, ev);
    expect(r.provider).toBe('github');
    expect(r.pushed.length).toBe(2);            // a + c; not b (passing)
    expect(r.pushed.every((p) => p.status === 'failed')).toBe(true);
    expect(calls).toBe(4);                       // 2x (search + create)
  });
});
