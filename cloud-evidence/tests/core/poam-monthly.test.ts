/**
 * Tests for core/poam-monthly.ts — the LOOP-E.E2 monthly POA&M delta workflow.
 *
 * Two layers:
 *   - Unit tests on computePoamDelta + renderPoamDeltaMarkdown using hand-built
 *     OSCAL POA&M documents (deterministic, no disk).
 *   - Integration tests on runPoamMonthly that emit real OSCAL POA&Ms from KSI
 *     evidence fixtures, thread revisions forward across two months, archive the
 *     document, and append the ledger.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  computePoamDelta,
  renderPoamDeltaMarkdown,
  runPoamMonthly,
  InvalidPoamMonthError,
  type PoamDeltaHeader,
} from '../../core/poam-monthly.ts';
import { readPoamLedger, poamArchiveRelPath, sha256Hex } from '../../core/poam-ledger.ts';
import type { OscalPoam, OscalPoamItem, OscalRisk, OscalPoamDocument } from '../../core/oscal-poam.ts';
import type { EvidenceFile, Finding, Severity } from '../../core/envelope.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-poam-monthly-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

// ─── Hand-built OSCAL POA&M helpers (for the delta unit tests) ────────────────

function mkItem(uuid: string, opts: { severity?: string; ksi?: string; rule?: string; riskUuid?: string } = {}): OscalPoamItem {
  const props = [{ name: 'severity', value: opts.severity ?? 'high' }];
  if (opts.ksi) props.push({ name: 'ksi-id', value: opts.ksi });
  if (opts.rule) props.push({ name: 'rule', value: opts.rule });
  return {
    uuid,
    title: `[${(opts.severity ?? 'high').toUpperCase()}] ${opts.ksi ?? 'KSI-X'} / ${opts.rule ?? 'rule'}`,
    description: 'failing finding',
    props,
    'related-risks': opts.riskUuid ? [{ 'risk-uuid': opts.riskUuid }] : undefined,
  };
}

function mkRisk(uuid: string, status: OscalRisk['status'], deadline?: string): OscalRisk {
  return { uuid, title: 't', description: 'd', statement: 's', status, deadline };
}

function mkDoc(opts: { items: OscalPoamItem[]; risks?: OscalRisk[]; lastModified?: string; version?: string }): OscalPoam {
  return {
    uuid: 'poam-uuid',
    metadata: {
      title: 'Acme — Plan of Action and Milestones',
      'last-modified': opts.lastModified ?? '2026-06-30T00:00:00Z',
      version: opts.version ?? 'r-1',
      'oscal-version': '1.1.2',
    },
    'system-id': { id: 'acme-prod', 'identifier-type': 'https://ietf.org/rfc/rfc4122' },
    risks: opts.risks,
    'poam-items': opts.items,
  };
}

// ─── KSI evidence fixtures (for the integration tests) ────────────────────────

function makeFinding(over: Partial<Finding> = {}): Finding {
  return {
    rule: over.rule ?? 'aws.iam.root_mfa_enabled',
    passed: over.passed ?? false,
    severity: (over.severity ?? 'high') as Severity,
    current_state: { summary: 'Root user MFA is NOT enabled.', observations: {} },
    target_state: { summary: 'Root MFA enabled.', rationale: 'Root compromise is catastrophic.' },
    gap: {
      description: 'Root account has no MFA device registered.',
      affected_resources: [
        { type: 'aws_iam_root_user', identifier: 'arn:aws:iam::123456789012:root', attributes: { account_id: '123456789012', region: 'us-east-1' } },
      ],
    },
    remediation: {
      summary: 'Register a hardware MFA token for the root user.',
      options: [{ approach: 'Register a YubiKey as root MFA', mechanism: 'console', steps: ['Log in as root.', 'Register the key.'] }],
    },
    nist_controls: over.nist_controls ?? ['ia-2.1'],
    applicable_key_word: 'MUST',
  } as Finding;
}

function writeKsiEvidence(out: string, over: { ksiId?: string; passed?: boolean; severity?: Severity; collected_at?: string } = {}): void {
  const ksiId = over.ksiId ?? 'KSI-IAM-MFA';
  const collected = over.collected_at ?? '2026-06-05T00:00:00Z';
  const env = {
    ksi_id: ksiId,
    ksi_name: 'Enforcing Phishing-Resistant MFA',
    ksi_statement: 'Enforce MFA using phishing-resistant methods.',
    scope: 'CLOUD',
    frmr_version: '0.9.43-beta',
    run_id: 'r-fixture',
    collected_at: collected,
    nist_controls: ['ia-2.1'],
    providers: [
      {
        provider: 'aws',
        account_id: '123456789012',
        region_set: ['us-east-1'],
        evidence: [{ source: 'iam.GetAccountSummary', captured_at: collected, data: { AccountMFAEnabled: 0 } }],
        findings: [makeFinding({ passed: over.passed, severity: over.severity })],
      },
    ],
    summary_for_llm: 'fixture',
  } as unknown as EvidenceFile;
  writeFileSync(resolve(out, `${ksiId}.json`), JSON.stringify(env, null, 2));
}

function baseOpts(out: string) {
  return { outDir: out, runId: 'run-1', frmrVersion: '0.9.43-beta', systemId: 'acme-prod', systemName: 'Acme Prod' };
}

const HEADER: PoamDeltaHeader = { runId: 'run-1', frmrVersion: '0.9.43-beta', signedManifestHref: 'manifest.json' };
const FIRST_MONTH_STATEMENT = 'First month of ConMon operation; no prior POA&M to compare against.';

// ─── computePoamDelta unit tests ──────────────────────────────────────────────

describe('computePoamDelta', () => {
  it('computes added items correctly', () => {
    const prior = mkDoc({ items: [mkItem('A', { ksi: 'KSI-IAM-MFA' })] });
    const current = mkDoc({ items: [mkItem('A', { ksi: 'KSI-IAM-MFA' }), mkItem('B', { ksi: 'KSI-CNA-NET', severity: 'medium' })] });
    const delta = computePoamDelta(prior, current, '2026-06', '2026-05');
    expect(delta.added.map((i) => i.uuid)).toEqual(['B']);
    expect(delta.closed).toHaveLength(0);
  });

  it('computes closed items correctly', () => {
    const prior = mkDoc({ items: [mkItem('A'), mkItem('B')] });
    const current = mkDoc({ items: [mkItem('A')] });
    const delta = computePoamDelta(prior, current, '2026-06', '2026-05');
    expect(delta.closed.map((i) => i.uuid)).toEqual(['B']);
    expect(delta.added).toHaveLength(0);
  });

  it('detects status_changed items', () => {
    const prior = mkDoc({ items: [mkItem('A', { riskUuid: 'R1' })], risks: [mkRisk('R1', 'open')] });
    const current = mkDoc({ items: [mkItem('A', { riskUuid: 'R1' })], risks: [mkRisk('R1', 'remediating')] });
    const delta = computePoamDelta(prior, current, '2026-06', '2026-05');
    expect(delta.status_changed).toHaveLength(1);
    expect(delta.status_changed[0]).toMatchObject({ uuid: 'A', prev_status: 'open', new_status: 'remediating' });
  });

  it('detects past_deadline items with correct days_past_deadline', () => {
    const current = mkDoc({
      items: [mkItem('A', { riskUuid: 'R1' })],
      risks: [mkRisk('R1', 'open', '2026-06-01T00:00:00Z')],
      lastModified: '2026-06-30T00:00:00Z',
    });
    const delta = computePoamDelta(null, current, '2026-06');
    expect(delta.past_deadline_items).toHaveLength(1);
    expect(delta.past_deadline_items[0]!.days_past_deadline).toBe(29);
  });

  it('first-month case computes empty added/closed (no prior to diff)', () => {
    const current = mkDoc({ items: [mkItem('A'), mkItem('B')] });
    const delta = computePoamDelta(null, current, '2026-06');
    expect(delta.added).toHaveLength(0);
    expect(delta.closed).toHaveLength(0);
    expect(delta.prior_month).toBeUndefined();
  });
});

// ─── renderPoamDeltaMarkdown unit tests ───────────────────────────────────────

describe('renderPoamDeltaMarkdown', () => {
  it('renders a Markdown delta with all 6 sections', () => {
    const prior = mkDoc({ items: [mkItem('A', { riskUuid: 'R1' })], risks: [mkRisk('R1', 'open')] });
    const current = mkDoc({ items: [mkItem('B', { ksi: 'KSI-CNA-NET', rule: 'sg_open', riskUuid: 'R2' })], risks: [mkRisk('R2', 'open', '2026-06-01T00:00:00Z')], lastModified: '2026-06-30T00:00:00Z' });
    const md = renderPoamDeltaMarkdown(computePoamDelta(prior, current, '2026-06', '2026-05'), HEADER);
    for (const heading of ['# Monthly POA&M Delta — 2026-06', '## Summary', '## Added items', '## Closed items', '## Status changes', '## Past-deadline items']) {
      expect(md).toContain(heading);
    }
  });

  it('first-month case emits the "no prior POA&M" delta cleanly', () => {
    const current = mkDoc({ items: [mkItem('A')] });
    const md = renderPoamDeltaMarkdown(computePoamDelta(null, current, '2026-06'), HEADER);
    expect(md).toContain(FIRST_MONTH_STATEMENT);
    expect(md).toContain('| Added items | 0 |');
    expect(md).toContain('| Closed items | 0 |');
  });
});

// ─── runPoamMonthly integration tests ─────────────────────────────────────────

describe('runPoamMonthly', () => {
  it('threads revisions history forward', () => {
    const out = tmp();
    writeKsiEvidence(out);
    runPoamMonthly({ ...baseOpts(out), runId: 'r-may', reportMonth: '2026-05' });
    runPoamMonthly({ ...baseOpts(out), runId: 'r-jun', reportMonth: '2026-06' });
    const jun = JSON.parse(readFileSync(resolve(out, 'poam.json'), 'utf8')) as OscalPoamDocument;
    const revs = jun['plan-of-action-and-milestones'].metadata.revisions ?? [];
    expect(revs).toHaveLength(1);
    expect(revs[0]!.version).toBe('r-may');
  });

  it('preserves deterministic UUIDs across months', () => {
    const out = tmp();
    writeKsiEvidence(out);
    runPoamMonthly({ ...baseOpts(out), runId: 'r-may', reportMonth: '2026-05' });
    const mayDoc = JSON.parse(readFileSync(resolve(out, poamArchiveRelPath('2026-05')), 'utf8')) as OscalPoamDocument;
    runPoamMonthly({ ...baseOpts(out), runId: 'r-jun', reportMonth: '2026-06' });
    const junDoc = JSON.parse(readFileSync(resolve(out, 'poam.json'), 'utf8')) as OscalPoamDocument;
    expect(junDoc['plan-of-action-and-milestones']['poam-items'][0]!.uuid)
      .toBe(mayDoc['plan-of-action-and-milestones']['poam-items'][0]!.uuid);
  });

  it('archives the POA&M to archive/poam-<YYYY-MM>.json', () => {
    const out = tmp();
    writeKsiEvidence(out);
    runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-06' });
    expect(existsSync(resolve(out, poamArchiveRelPath('2026-06')))).toBe(true);
  });

  it('ledger entry sha256 matches archived file sha256', () => {
    const out = tmp();
    writeKsiEvidence(out);
    const res = runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-06' });
    const archiveBuf = readFileSync(resolve(out, poamArchiveRelPath('2026-06')));
    expect(res.ledgerEntry!.sha256).toBe(sha256Hex(archiveBuf));
  });

  it('throws when reportMonth is malformed (not YYYY-MM)', () => {
    const out = tmp();
    expect(() => runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-6' })).toThrow(InvalidPoamMonthError);
  });

  it('skipped_reason=no-failing-findings propagates without ledger growth', () => {
    const out = tmp();
    writeKsiEvidence(out, { passed: true });
    const res = runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-06' });
    expect(res.poamPath).toBeNull();
    expect(res.skipped_reason).toBe('no-failing-findings');
    expect(readPoamLedger(out)).toHaveLength(0);
    expect(existsSync(resolve(out, 'poam-delta-2026-06.md'))).toBe(false);
  });

  it('past_deadline severity rollup matches the remediation deadline table', () => {
    const out = tmp();
    // A high-severity finding collected long ago → FedRAMP CMP deadline elapsed.
    writeKsiEvidence(out, { severity: 'high', collected_at: '2020-01-01T00:00:00Z' });
    const res = runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-06' });
    expect(res.delta!.past_deadline_items.length).toBeGreaterThanOrEqual(1);
    expect(res.delta!.past_deadline_items[0]!.severity).toBe('high');
    expect(res.delta!.past_deadline_items[0]!.days_past_deadline).toBeGreaterThan(0);
  });

  it('integrates with --oscal-poam end-to-end on real fixtures', () => {
    const out = tmp();
    writeKsiEvidence(out);
    const res = runPoamMonthly({ ...baseOpts(out), reportMonth: '2026-06' });
    expect(res.poamPath).not.toBeNull();
    expect(existsSync(res.deltaPath!)).toBe(true);
    expect(existsSync(resolve(out, 'poam.json'))).toBe(true);
    expect(readPoamLedger(out)).toHaveLength(1);
    expect(res.delta).not.toBeNull();
    expect(res.priorMonth).toBeNull();
  });
});
