/**
 * Tests for core/siem-push.ts — OCSF event building + batched HTTP push.
 */
import { describe, it, expect } from 'vitest';
import { buildOcsfEvent, pushToSiem, pushEvidenceToSiem } from '../../core/siem-push.ts';
import type { Finding, EvidenceFile } from '../../core/envelope.ts';

function mkFinding(rule: string, passed: boolean, severity: Finding['severity'] = 'high'): Finding {
  return {
    rule, passed, severity,
    current_state: { summary: `Summary for ${rule}`, observations: null },
    target_state: { summary: 'x', rationale: 'x' },
    nist_controls: ['IA-2', 'IA-2(1)'],
    ...(passed ? {} : {
      gap: { description: 'x', affected_resources: [{ type: 'aws_iam_user', identifier: 'arn:aws:iam::1:user/bob', name: 'bob' }] },
      remediation: { summary: 'x', options: [{ approach: 'x', mechanism: 'cli', steps: ['s'] }] },
    }),
  };
}

function mkEvidence(findings: Finding[]): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'MFA',
    ksi_statement: 'x',
    scope: 'CLOUD',
    frmr_version: '2025-06.r1',
    run_id: 'run-test-1',
    collected_at: '2026-05-27T12:00:00Z',
    providers: [{ provider: 'aws', account_id: '111122223333', region_set: ['us-east-1'], evidence: [], findings }],
    rollup: { pass: false, passing_findings: 0, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

describe('buildOcsfEvent', () => {
  it('emits a v1.2 compliance_finding event for a failing finding', () => {
    const f = mkFinding('aws.iam.root_mfa', false, 'critical');
    const ev = mkEvidence([f]);
    const out = buildOcsfEvent(f, ev, '111122223333', 'aws', 'us-east-1');
    expect(out.class_uid).toBe(2003);
    expect(out.class_name).toBe('Compliance Finding');
    expect(out.severity_id).toBe(5);
    expect(out.severity).toBe('Critical');
    expect(out.compliance.status).toBe('Fail');
    expect(out.compliance.requirements).toEqual(['IA-2', 'IA-2(1)']);
    expect(out.finding_info.uid).toBe('KSI-IAM-MFA|aws.iam.root_mfa|aws|111122223333');
    expect(out.cloud.provider).toBe('AWS');
    expect(out.cloud.account?.uid).toBe('111122223333');
    expect(out.cloud.region).toBe('us-east-1');
    expect(out.resources?.length).toBe(1);
    expect(out.resources?.[0].uid).toContain('bob');
  });

  it('marks status Pass for a passing finding', () => {
    const f = mkFinding('aws.iam.root_mfa', true, 'info');
    const ev = mkEvidence([f]);
    const out = buildOcsfEvent(f, ev, '111122223333', 'aws', 'us-east-1');
    expect(out.compliance.status).toBe('Pass');
    expect(out.severity_id).toBe(1);
    expect(out.severity).toBe('Informational');
  });

  it('maps gcp / k8s providers correctly', () => {
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const gcpEvent = buildOcsfEvent(f, ev, 'my-project', 'gcp');
    expect(gcpEvent.cloud.provider).toBe('GCP');
    expect(gcpEvent.cloud.project_uid).toBe('my-project');

    const k8sEvent = buildOcsfEvent(f, ev, 'prod-cluster', 'k8s');
    expect(k8sEvent.cloud.provider).toBe('Kubernetes');
  });
});

describe('pushToSiem batching + format', () => {
  it('sends a single batch when events <= batchSize', async () => {
    const calls: Array<{ url: string; body: string }> = [];
    const httpPost = async (url: string, _h: any, body: string) => {
      calls.push({ url, body });
      return { status: 200, body: '{}' };
    };
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const events = [buildOcsfEvent(f, ev, '1', 'aws')];
    const r = await pushToSiem(events, { url: 'https://siem.example/intake', httpPost });
    expect(r.batches_sent).toBe(1);
    expect(r.events_sent).toBe(1);
    expect(r.failures).toEqual([]);
    expect(calls).toHaveLength(1);
  });

  it('splits into multiple batches when events > batchSize', async () => {
    let count = 0;
    const httpPost = async () => { count++; return { status: 200, body: '{}' }; };
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const events = Array.from({ length: 250 }, () => buildOcsfEvent(f, ev, '1', 'aws'));
    const r = await pushToSiem(events, { url: 'https://x', httpPost, batchSize: 100 });
    expect(r.batches_sent).toBe(3); // 100, 100, 50
    expect(r.events_sent).toBe(250);
    expect(count).toBe(3);
  });

  it('records failures per batch on non-2xx', async () => {
    const httpPost = async () => ({ status: 429, body: 'rate-limited' });
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const events = [buildOcsfEvent(f, ev, '1', 'aws')];
    const r = await pushToSiem(events, { url: 'https://x', httpPost });
    expect(r.batches_sent).toBe(0);
    expect(r.failures.length).toBeGreaterThan(0);
    expect(r.failures[0].status).toBe(429);
  });

  it('uses splunk-hec wire format when requested', async () => {
    let captured = '';
    const httpPost = async (_u: any, _h: any, body: string) => { captured = body; return { status: 200, body: '{}' }; };
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const events = [buildOcsfEvent(f, ev, '1', 'aws')];
    await pushToSiem(events, { url: 'https://splunk:8088/services/collector', httpPost, format: 'splunk-hec' });
    const parsed = JSON.parse(captured);
    expect(parsed.event).toBeTruthy();
    expect(parsed.sourcetype).toBe('fedramp-20x:ocsf');
  });

  it('attaches authorization + extra headers', async () => {
    let capturedHeaders: any = {};
    const httpPost = async (_u: any, headers: any) => { capturedHeaders = headers; return { status: 200, body: '{}' }; };
    const f = mkFinding('rule', false);
    const ev = mkEvidence([f]);
    const events = [buildOcsfEvent(f, ev, '1', 'aws')];
    await pushToSiem(events, {
      url: 'https://x',
      httpPost,
      authHeader: 'Splunk abc-123',
      extraHeaders: { 'X-Custom': 'value' },
    });
    expect(capturedHeaders.authorization).toBe('Splunk abc-123');
    expect(capturedHeaders['X-Custom']).toBe('value');
  });
});

describe('pushEvidenceToSiem', () => {
  it('emits one event per finding in the evidence file', async () => {
    let totalEvents = 0;
    const httpPost = async (_u: any, _h: any, body: string) => {
      totalEvents += body.split('\n').filter(Boolean).length;
      return { status: 200, body: '{}' };
    };
    const ev = mkEvidence([mkFinding('a', false), mkFinding('b', true), mkFinding('c', false)]);
    const r = await pushEvidenceToSiem(ev, { url: 'https://x', httpPost });
    expect(r.events_sent).toBe(3); // ALL findings, passing + failing
    expect(totalEvents).toBe(3);
  });
});

describe('pushToSiem failure reporting', () => {
  it('records a per-batch failure with the HTTP status (partial-success report)', async () => {
    const ev = buildOcsfEvent(mkFinding('a', false), mkEvidence([mkFinding('a', false)]), '1', 'aws');
    const httpPost = async () => ({ status: 503, body: 'service unavailable' });
    const r = await pushToSiem([ev], { url: 'https://x', httpPost });
    expect(r.batches_sent).toBe(0);
    expect(r.events_sent).toBe(0);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]!.status).toBe(503);
  });

  it('annotates a thrown network error with its code (ECONNREFUSED)', async () => {
    const ev = buildOcsfEvent(mkFinding('a', false), mkEvidence([mkFinding('a', false)]), '1', 'aws');
    const httpPost = async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); };
    const r = await pushToSiem([ev], { url: 'https://x', httpPost });
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]!.reason).toContain('ECONNREFUSED');
  });
});
