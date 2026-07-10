/**
 * Offline tests for the VDR live-scan collectors (P5a).
 * Feeds synthetic Inspector2 / Container-Analysis shapes to the pure converters,
 * runs them through the real ledger + KEV join + summary, and asserts a
 * KEV-overdue CVE surfaces as an SLA breach. No live cloud calls.
 */
import { describe, it, expect } from 'vitest';
import { toLedgerEntries, normalizeSeverity, buildVdrFindings } from '../../providers/aws/vdr-scan.ts';
import { toGcpLedgerEntries } from '../../providers/gcp/vdr-scan.ts';
import { buildLedger } from '../../core/vdr-ledger.ts';
import { summarizeVdr } from '../../core/vdr-report.ts';
import type { KevCatalog } from '../../core/kev-feed.ts';
import { KSI_MAP } from '../../core/ksi-map.ts';

const NOW = '2026-05-28T00:00:00Z';

function kevCatalog(entries: Array<{ cve: string; dueDate: string }>): KevCatalog {
  const byCve = new Map<string, any>();
  for (const e of entries) byCve.set(e.cve.toUpperCase(), { cveID: e.cve, dueDate: e.dueDate, dateAdded: '2026-01-01' });
  return { byCve, count: byCve.size, source: 'file', warnings: [] };
}

describe('normalizeSeverity', () => {
  it('maps Inspector severities to the ledger scale', () => {
    expect(normalizeSeverity('CRITICAL')).toBe('critical');
    expect(normalizeSeverity('HIGH')).toBe('high');
    expect(normalizeSeverity('UNTRIAGED')).toBe('info');
  });
});

describe('AWS toLedgerEntries', () => {
  it('extracts CVE, severity, resource from an Inspector2 finding', () => {
    const entries = toLedgerEntries([{
      severity: 'CRITICAL',
      firstObservedAt: '2025-01-01T00:00:00Z',
      status: 'ACTIVE',
      packageVulnerabilityDetails: { vulnerabilityId: 'CVE-2021-44228' },
      resources: [{ id: 'arn:aws:ecr:us-east-1:111122223333:repository/app' }],
    }]);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.cve).toBe('CVE-2021-44228');
    expect(entries[0]!.severity).toBe('critical');
    expect(entries[0]!.kev).toBe(false);
  });
});

describe('GCP toGcpLedgerEntries', () => {
  it('extracts the CVE from the note name', () => {
    const entries = toGcpLedgerEntries([{
      noteName: 'projects/goog-vulnz/notes/CVE-2021-44228',
      resourceUri: 'https://us-docker.pkg.dev/p/r/app@sha256:abc',
      createTime: '2025-02-01T00:00:00Z',
      vulnerability: { effectiveSeverity: 'CRITICAL' },
    }]);
    expect(entries[0]!.cve).toBe('CVE-2021-44228');
    expect(entries[0]!.severity).toBe('critical');
  });
});

describe('KEV-overdue → SLA breach', () => {
  it('flags a KEV CVE past its due date as an overdue breach (AWS path)', () => {
    const raw = [{ severity: 'HIGH', firstObservedAt: '2025-01-01T00:00:00Z', status: 'ACTIVE', packageVulnerabilityDetails: { vulnerabilityId: 'CVE-2024-0001' }, resources: [{ id: 'res-1' }] }];
    const kev = kevCatalog([{ cve: 'CVE-2024-0001', dueDate: '2025-02-01' }]); // due long before NOW
    const ledger = buildLedger(toLedgerEntries(raw), kev, { tier: 'moderate', now: NOW });
    const summary = summarizeVdr(ledger, NOW);
    expect(ledger[0]!.kev).toBe(true);
    expect(summary.kev_count).toBe(1);
    expect(summary.overdue).toBeGreaterThanOrEqual(1);
    expect(summary.sla_breaches.length).toBeGreaterThanOrEqual(1);
  });
});

describe('buildVdrFindings', () => {
  it('produces a passing capability finding + breach finding, with provider-scoped rule names', () => {
    const summary = summarizeVdr([], NOW);
    const aws = buildVdrFindings(true, summary, 'file', 'MUST', '111122223333', 'aws');
    const gcp = buildVdrFindings(true, summary, 'file', 'MUST', 'proj', 'gcp');
    expect(aws[0]!.rule).toBe('aws.vdr.detection_capability_enabled');
    expect(gcp[0]!.rule).toBe('gcp.vdr.detection_capability_enabled');
    expect(aws[0]!.passed).toBe(true);
    expect(aws[1]!.passed).toBe(true); // no findings → no breaches
  });

  it('does NOT false-pass "no SLA breaches" when detection is disabled (findings unreadable)', () => {
    // Regression: overdue===0 is vacuous if the scanner never enumerated findings.
    const summary = summarizeVdr([], NOW);
    const aws = buildVdrFindings(false, summary, 'none', 'MUST', '111122223333', 'aws');
    expect(aws[0]!.rule).toBe('aws.vdr.detection_capability_enabled');
    expect(aws[0]!.passed).toBe(false);           // detection off → capability fails
    expect(aws[1]!.rule).toBe('aws.vdr.no_sla_breaches');
    expect(aws[1]!.passed).toBe(false);           // must be gated, not a false PASS
    // A failing finding must still carry gap + remediation (schema invariant).
    expect(aws[1]!.gap?.affected_resources.length).toBeGreaterThan(0);
    expect(aws[1]!.remediation?.options.length).toBeGreaterThan(0);
  });
});

describe('KSI-AFR-VDR registration', () => {
  it('is registered with aws + gcp collectors', () => {
    const e = KSI_MAP['KSI-AFR-VDR'];
    expect(e).toBeTruthy();
    expect(typeof e!.aws).toBe('function');
    expect(typeof e!.gcp).toBe('function');
  });
});
