/**
 * Tests for core/deadline-engine.ts — the LOOP-B.B2 priority-cascading
 * remediation deadline engine (operator override → CISA KEV → PAIN/IRV/LEV →
 * FedRAMP CMP → observable severity-fallback).
 */
import { describe, it, expect } from 'vitest';
import { computeDeadline, type DeadlineContext } from '../../core/deadline-engine.ts';
import { FEDRAMP_CMP_DEADLINES } from '../../core/deadline-table.ts';
import type { Finding } from '../../core/envelope.ts';
import type { KevEntry } from '../../core/kev-feed.ts';

function finding(p: Partial<Finding> & { severity: Finding['severity'] }): Finding {
  return { rule: 'r', passed: false, ...p } as Finding;
}
function withCve(severity: Finding['severity'], cves: string[], extra: Partial<Finding> = {}): Finding {
  return finding({ severity, references: cves.map((c) => ({ title: c, url: 'https://nvd', cve_id: c })), ...extra });
}
function kev(entries: Array<Partial<KevEntry> & { cveID: string; dueDate: string }>): Map<string, KevEntry> {
  const m = new Map<string, KevEntry>();
  for (const e of entries) m.set(e.cveID.toUpperCase(), { dateAdded: '2021-12-10', ...e } as KevEntry);
  return m;
}
const COLLECTED = '2026-01-01T00:00:00.000Z';
const ctx = (over: Partial<DeadlineContext> = {}): DeadlineContext => ({ now: () => new Date('2026-06-06T00:00:00Z'), ...over });

describe('computeDeadline cascade', () => {
  it('uses the CISA KEV dueDate verbatim when a CVE matches the catalog', () => {
    const r = computeDeadline(
      withCve('high', ['CVE-2021-44228']),
      ctx({ kevIndex: kev([{ cveID: 'CVE-2021-44228', dueDate: '2021-12-24' }]) }),
      COLLECTED,
    );
    expect(r.source).toBe('kev');
    expect(r.deadline).toBe('2021-12-24T00:00:00.000Z');
    expect(r.kev_entry?.cveID).toBe('CVE-2021-44228');
  });

  it('does NOT synthesize +21d — the deadline equals the catalog dueDate exactly', () => {
    const r = computeDeadline(
      withCve('low', ['CVE-2021-44228']),
      ctx({ kevIndex: kev([{ cveID: 'CVE-2021-44228', dueDate: '2021-12-24', dateAdded: '2021-12-10' }]) }),
      COLLECTED,
    );
    // dateAdded + 21d would be 2021-12-31; the catalog dueDate (2021-12-24) wins.
    expect(r.deadline.slice(0, 10)).toBe('2021-12-24');
  });

  it('takes the earliest dueDate when multiple KEV CVEs match the finding', () => {
    const r = computeDeadline(
      withCve('high', ['CVE-2021-1', 'CVE-2021-2', 'CVE-2021-3']),
      ctx({ kevIndex: kev([
        { cveID: 'CVE-2021-1', dueDate: '2026-03-01' },
        { cveID: 'CVE-2021-2', dueDate: '2026-02-01' },
        { cveID: 'CVE-2021-3', dueDate: '2026-04-01' },
      ]) }),
      COLLECTED,
    );
    expect(r.deadline.slice(0, 10)).toBe('2026-02-01');
    expect(r.kev_entry?.cveID).toBe('CVE-2021-2');
  });

  it('falls through to the FedRAMP CMP table when there is no KEV match', () => {
    const r = computeDeadline(withCve('high', ['CVE-2099-9']), ctx({ kevIndex: kev([]) }), COLLECTED);
    expect(r.source).toBe('fedramp-cmp');
    expect(r.days_from_collected).toBe(FEDRAMP_CMP_DEADLINES.high);   // 30
    expect(r.deadline.slice(0, 10)).toBe('2026-01-31');              // 2026-01-01 + 30d
  });

  it('applies the PAIN/IRV/LEV override when composite ≥ 9 and IRV + LEV are true', () => {
    const f = finding({ severity: 'medium', irv: true, lev: true, risk_score: { composite_score: 9.5 } as any });
    const r = computeDeadline(f, ctx(), COLLECTED);
    expect(r.source).toBe('pain-irv-lev');
    expect(r.days_from_collected).toBe(FEDRAMP_CMP_DEADLINES.critical);   // derived from table (Q2)
    expect(r.pain_irv_lev?.composite_score).toBe(9.5);
  });

  it('does NOT apply the PAIN/IRV/LEV override when composite < 9', () => {
    const f = finding({ severity: 'medium', irv: true, lev: true, risk_score: { composite_score: 8.5 } as any });
    const r = computeDeadline(f, ctx(), COLLECTED);
    expect(r.source).toBe('fedramp-cmp');
    expect(r.days_from_collected).toBe(FEDRAMP_CMP_DEADLINES.medium);   // 90
  });

  it('derives LEV from EPSS percentile ≥ 0.95 when no explicit lev flag', () => {
    const f = finding({ severity: 'low', irv: true, risk_score: { composite_score: 9.1, epss: { percentile: 0.97 } } as any });
    const r = computeDeadline(f, ctx(), COLLECTED);
    expect(r.source).toBe('pain-irv-lev');
    expect(r.pain_irv_lev?.lev).toBe(true);
  });

  it('honours an operator override when no KEV mandate applies', () => {
    const r = computeDeadline(
      finding({ severity: 'high' }),
      ctx({ acceptanceOverride: { deadline: '2026-09-01T00:00:00.000Z', uuid: 'accept-1' } }),
      COLLECTED,
    );
    expect(r.source).toBe('operator-override');
    expect(r.deadline).toBe('2026-09-01T00:00:00.000Z');
    expect(r.operator_override?.uuid).toBe('accept-1');
  });

  it('caps an operator override at the earlier KEV federal mandate (Q1)', () => {
    const r = computeDeadline(
      withCve('high', ['CVE-2021-44228']),
      ctx({
        kevIndex: kev([{ cveID: 'CVE-2021-44228', dueDate: '2026-02-01' }]),
        acceptanceOverride: { deadline: '2026-09-01T00:00:00.000Z', uuid: 'accept-2' },   // later than KEV
      }),
      COLLECTED,
    );
    expect(r.source).toBe('kev');                                    // KEV wins — cannot be extended
    expect(r.deadline.slice(0, 10)).toBe('2026-02-01');
    expect(r.rationale).toMatch(/capped by CISA KEV/);
  });

  it('reports severity-fallback (with a REQUIRES-OPERATOR-INPUT marker) when the CMP table lacks a severity', () => {
    const r = computeDeadline(
      finding({ severity: 'medium' }),
      ctx({ cmpTable: { critical: 15, high: 30, low: 180, info: 365 } }),   // medium missing
      COLLECTED,
    );
    expect(r.source).toBe('severity-fallback');
    expect(r.rationale).toMatch(/REQUIRES-OPERATOR-INPUT/);
  });

  it('falls back to now() with a note when collected_at is unparseable', () => {
    const r = computeDeadline(finding({ severity: 'low' }), ctx(), 'not-a-date');
    expect(r.source).toBe('fedramp-cmp');
    expect(r.rationale).toMatch(/unparseable|current time/);
    // Anchored at now (2026-06-06) + 180d.
    expect(r.deadline.slice(0, 7)).toBe('2026-12');
  });

  it('skips the KEV branch entirely when no kevIndex is supplied', () => {
    const r = computeDeadline(withCve('critical', ['CVE-2021-44228']), ctx(), COLLECTED);
    expect(r.source).toBe('fedramp-cmp');
    expect(r.days_from_collected).toBe(FEDRAMP_CMP_DEADLINES.critical);
  });

  it('maps info-severity findings to the CMP info row (365 days)', () => {
    const r = computeDeadline(finding({ severity: 'info' }), ctx({ kevIndex: kev([]) }), COLLECTED);
    expect(r.source).toBe('fedramp-cmp');
    expect(r.days_from_collected).toBe(365);
  });
});
