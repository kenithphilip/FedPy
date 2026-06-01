/**
 * Tests for core/scn-classifier.ts (SCN-1).
 *
 * Verifies:
 *   1. Rule matching — significant vs advisory vs not-significant per category.
 *   2. Harvesting from diff-report.json + inventory-diff.json shapes.
 *   3. Categorization heuristics (auth/crypto/network/boundary/personnel).
 *   4. Totals aggregation.
 *   5. Draft-notice markdown rendering (consolidated artifacts, recommended notice).
 *   6. End-to-end disk reader (buildScnReport / writeScnReport).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  classifyChange,
  classifyChanges,
  harvestChanges,
  buildScnReport,
  writeScnReport,
  draftNotice,
  DEFAULT_RULES,
  type ScnChange,
  type ScnReport,
} from '../../core/scn-classifier.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-scn-'));
  dirs.push(d);
  return d;
}
afterEach(() => { for (const d of dirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* */ } } });

describe('classifyChange (rule matching)', () => {
  it('classifies a new boundary as SIGNIFICANT with a 30-day notice', () => {
    const r = classifyChange({ id: 'b1', description: 'New subscription added', source: 'inventory-diff', category: 'boundary' });
    expect(r.significance).toBe('significant');
    expect(r.recommended_notice_days).toBe(30);
    expect(r.rule_id).toBe('scn-r-boundary-new');
    expect(r.required_artifacts.length).toBeGreaterThan(0);
  });

  it('classifies an authentication change as SIGNIFICANT', () => {
    const r = classifyChange({ id: 'a1', description: 'Removed SAML provider', source: 'inventory-diff', category: 'authentication' });
    expect(r.significance).toBe('significant');
    expect(r.recommended_notice_days).toBe(30);
  });

  it('classifies a configuration regression as ADVISORY (7-day notice)', () => {
    const r = classifyChange({ id: 'c1', description: 'Logging finding regressed', source: 'finding-diff', category: 'configuration' });
    expect(r.significance).toBe('advisory');
    expect(r.recommended_notice_days).toBe(7);
  });

  it('classifies a platform-major upgrade as ADVISORY (14-day notice)', () => {
    const r = classifyChange({ id: 'p1', description: 'GKE 1.26 → 1.27', source: 'proposed', category: 'platform-version' });
    expect(r.significance).toBe('advisory');
    expect(r.recommended_notice_days).toBe(14);
  });

  it('classifies an improvement as NOT-SIGNIFICANT (no notice)', () => {
    const r = classifyChange({ id: 'i1', description: 'Finding now passes', source: 'finding-diff', category: 'improvement' });
    expect(r.significance).toBe('not-significant');
    expect(r.recommended_notice_days).toBeNull();
    expect(r.required_artifacts).toEqual([]);
  });

  it('returns the default (not-significant) for unmatched changes', () => {
    const r = classifyChange({ id: 'x1', description: 'something odd', source: 'proposed', category: 'other' });
    expect(r.significance).toBe('not-significant');
    expect(r.rule_id).toBe('default');
  });

  it('respects rule order and honours custom predicates', () => {
    const custom = [
      { id: 'high-priority-mfa', description: 'MFA-specific change', category: 'authentication' as const, matches: (c: ScnChange) => /mfa/i.test(c.description), significance: 'significant' as const, recommended_notice_days: 45, required_artifacts: ['custom artifact'] },
      ...DEFAULT_RULES,
    ];
    const r = classifyChange({ id: 'm1', description: 'MFA enforcement disabled', source: 'finding-diff', category: 'authentication' }, custom);
    expect(r.rule_id).toBe('high-priority-mfa');
    expect(r.recommended_notice_days).toBe(45);
    expect(r.required_artifacts).toContain('custom artifact');
  });
});

describe('harvestChanges (diff-report + inventory-diff)', () => {
  it('emits a regression change from diff-report.json finding regressions', () => {
    const changes = harvestChanges({
      diffSummary: { ksi_diffs: [{ ksi_id: 'KSI-MLA-ALA', finding_changes: [
        { rule: 'aws:cloudtrail.delivers_to_cloudwatch', change: 'regressed', current: { passed: false }, previous: { passed: true } },
      ] }] },
      inventoryDiff: null,
    });
    expect(changes).toHaveLength(1);
    expect(changes[0]!.source).toBe('finding-diff');
    expect(changes[0]!.category).toBe('configuration');     // categorize hit "cloudtrail"
    expect(changes[0]!.description).toContain('regressed');
  });

  it('flags "fixed" findings as IMPROVEMENT (never a notification trigger)', () => {
    const changes = harvestChanges({
      diffSummary: { ksi_diffs: [{ ksi_id: 'KSI-IAM-MFA', finding_changes: [
        { rule: 'aws:iam.console_users_have_mfa', change: 'fixed', current: { passed: true }, previous: { passed: false } },
      ] }] },
      inventoryDiff: null,
    });
    expect(changes[0]!.category).toBe('improvement');
    const cls = classifyChange(changes[0]!);
    expect(cls.significance).toBe('not-significant');
  });

  it('categorises an inventory-added asset by id substring (KMS → cryptography)', () => {
    const changes = harvestChanges({
      diffSummary: null,
      inventoryDiff: { generated_at: 'now', previous_count: 1, current_count: 2, added: ['arn:aws:kms:us-east-1:111:key/abc'], removed: [], changed: [] } as any,
    });
    expect(changes).toHaveLength(1);
    expect(changes[0]!.category).toBe('cryptography');
    expect(changes[0]!.affected?.[0]?.identifier).toContain('kms');
  });

  it('uses field-aware categorisation on changed assets (publicFacing → network)', () => {
    const changes = harvestChanges({
      diffSummary: null,
      inventoryDiff: { generated_at: 'now', previous_count: 1, current_count: 1, added: [], removed: [], changed: [{ id: 'sub-1/sa1', fields: ['publicFacing'] }] } as any,
    });
    expect(changes[0]!.category).toBe('network');
  });

  it('passes operator-proposed changes through unchanged', () => {
    const proposed: ScnChange[] = [{ id: 'p1', description: 'Add Okta as IdP', source: 'proposed', category: 'authentication' }];
    const changes = harvestChanges({ diffSummary: null, inventoryDiff: null, proposed });
    expect(changes).toEqual(proposed);
  });
});

describe('classifyChanges + totals', () => {
  it('aggregates by significance', () => {
    const changes: ScnChange[] = [
      { id: '1', description: '...', source: 'proposed', category: 'boundary' },           // significant
      { id: '2', description: '...', source: 'proposed', category: 'platform-version' },   // advisory
      { id: '3', description: '...', source: 'proposed', category: 'configuration' },      // advisory
      { id: '4', description: '...', source: 'proposed', category: 'improvement' },        // not-significant
    ];
    const classifications = classifyChanges(changes);
    const totals = {
      significant: classifications.filter((c) => c.significance === 'significant').length,
      advisory: classifications.filter((c) => c.significance === 'advisory').length,
      not_significant: classifications.filter((c) => c.significance === 'not-significant').length,
    };
    expect(totals).toEqual({ significant: 1, advisory: 2, not_significant: 1 });
  });
});

describe('draftNotice (markdown render)', () => {
  function tinyReport(): ScnReport {
    const changes: ScnChange[] = [
      { id: 'b', description: 'New subscription added', source: 'inventory-diff', category: 'boundary', affected: [{ type: 'azure_subscription', identifier: 'sub-99' }] },
      { id: 'c', description: 'Logging regressed', source: 'finding-diff', category: 'configuration' },
    ];
    const classifications = classifyChanges(changes);
    return {
      run_id: 'r-1', generated_at: '2026-01-01T00:00:00Z',
      totals: { significant: 1, advisory: 1, not_significant: 0, total: 2 },
      classifications, draft_notice: '',
    };
  }

  it('renders a notice that lists significant + advisory changes and consolidated artifacts', () => {
    const md = draftNotice(tinyReport(), { systemName: 'Acme Cloud', csp: 'Acme Corp' });
    expect(md).toContain('Significant Change Notification (SCN) — DRAFT');
    expect(md).toContain('Acme Cloud');
    expect(md).toContain('Acme Corp');
    expect(md).toContain('New subscription added');
    expect(md).toContain('Logging regressed');
    expect(md).toContain('Updated SSP authorization-boundary diagram');
    expect(md).toContain('POA&M');
    expect(md).toMatch(/Recommended advance notice:[^\n]*\b30\b[^\n]*day/);
  });

  it('renders a "none required" message when nothing is significant or advisory', () => {
    const empty: ScnReport = { run_id: 'r', generated_at: 't', totals: { significant: 0, advisory: 0, not_significant: 0, total: 0 }, classifications: [], draft_notice: '' };
    expect(draftNotice(empty)).toContain('none required');
  });
});

describe('buildScnReport / writeScnReport (disk path)', () => {
  it('reads diff-report.json + inventory-diff.json from outDir and writes both outputs', () => {
    const out = tmp();
    writeFileSync(join(out, 'diff-report.json'), JSON.stringify({
      current_run: 'r2', previous_run: 'r1', total_changes: 1, regressed_count: 1, fixed_count: 0, new_findings_count: 0,
      ksi_diffs: [{ ksi_id: 'KSI-MLA-ALA', finding_changes: [{ rule: 'aws:cloudtrail.delivers_to_cloudwatch', change: 'regressed', current: { passed: false } }] }],
    }));
    writeFileSync(join(out, 'inventory-diff.json'), JSON.stringify({
      generated_at: 'now', previous_count: 1, current_count: 2, added: ['/subscriptions/sub-99'], removed: [], changed: [],
    }));
    const report = buildScnReport({ outDir: out, runId: 'r2', systemName: 'Acme Cloud' });
    expect(report.totals.significant).toBeGreaterThanOrEqual(1);
    expect(report.classifications.some((c) => c.change.source === 'inventory-diff')).toBe(true);

    writeScnReport(report, join(out, 'scn-classification.json'), join(out, 'scn-notice-draft.md'));
    const onDisk = JSON.parse(readFileSync(join(out, 'scn-classification.json'), 'utf8'));
    expect(onDisk.run_id).toBe('r2');
    const notice = readFileSync(join(out, 'scn-notice-draft.md'), 'utf8');
    expect(notice).toContain('Significant Change Notification');
  });

  it('handles a totally empty outDir gracefully (no diff files)', () => {
    const out = tmp();
    const r = buildScnReport({ outDir: out, runId: 'fresh' });
    expect(r.totals.total).toBe(0);
    expect(r.draft_notice).toContain('none required');
  });

  it('imports a proposed-changes JSON file (both array and {changes:[]} shapes)', () => {
    const out = tmp();
    const proposedArr = join(out, 'proposed-arr.json');
    const proposedObj = join(out, 'proposed-obj.json');
    writeFileSync(proposedArr, JSON.stringify([{ id: 'p1', description: 'Add Okta', source: 'proposed', category: 'authentication' }]));
    writeFileSync(proposedObj, JSON.stringify({ changes: [{ id: 'p2', description: 'Replace KMS provider', source: 'proposed', category: 'cryptography' }] }));
    const r1 = buildScnReport({ outDir: out, runId: 'r', proposedChangesPath: proposedArr });
    const r2 = buildScnReport({ outDir: out, runId: 'r', proposedChangesPath: proposedObj });
    expect(r1.classifications.some((c) => c.change.id === 'p1')).toBe(true);
    expect(r2.classifications.some((c) => c.change.id === 'p2')).toBe(true);
  });
});
