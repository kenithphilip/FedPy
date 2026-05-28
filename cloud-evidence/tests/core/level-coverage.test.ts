/**
 * Tests for the impact-level coverage foundation (Phase 2):
 *   - requirements-registry: level selection, actor-scope, high-derivation
 *   - bizdays: business-day math + deadline status
 *   - process-artifact-tracker: attested/unattested/awareness/SLA, schema-valid output
 */
import { describe, it, expect } from 'vitest';
import {
  loadRequirements, selectForLevel, appliesAtLevel, actorScopeOf, getRequirement,
} from '../../core/requirements-registry.ts';
import { addBusinessDays, isBusinessDay, deadlineStatus, usFederalHolidays } from '../../core/bizdays.ts';
import { buildProcessArtifactEvidence } from '../../core/process-artifact-tracker.ts';
import { validateEvidenceFile } from '../../core/schema.ts';

describe('requirements-registry', () => {
  it('loads the full 20x requirement set', () => {
    const all = loadRequirements();
    expect(all.length).toBeGreaterThan(200);
    expect(all.some((r) => r.id === 'KSI-IAM-MFA')).toBe(true);
    expect(all.some((r) => r.id === 'VDR-CSO-DET')).toBe(true);
  });

  it('partitions in-scope vs awareness vs not-applicable for a tier', () => {
    const sel = selectForLevel('moderate');
    expect(sel.inScope.length).toBeGreaterThan(0);
    // Awareness items obligate FedRAMP/agency/3PAO (e.g. VDR-AGM-*, FSI-FRP-*).
    expect(sel.awareness.length).toBeGreaterThan(0);
    // No requirement appears in two buckets.
    const ids = new Set<string>();
    for (const r of [...sel.inScope, ...sel.awareness, ...sel.notApplicable]) {
      expect(ids.has(r.id)).toBe(false);
      ids.add(r.id);
    }
  });

  it('classifies actor scope from affects/actor', () => {
    const ksi = getRequirement('KSI-IAM-MFA')!;
    expect(actorScopeOf(ksi)).toBe('provider');
    // A FedRAMP-obligation requirement should not be provider-scope.
    const frp = loadRequirements().find((r) => r.actor === 'FRP' || /-FRP-/.test(r.id));
    if (frp) expect(actorScopeOf(frp)).not.toBe('provider');
  });

  it('derives High from Rev5 when controls[] exist, else marks pending', () => {
    const withControls = loadRequirements().find((r) => (r.controls?.length ?? 0) > 0)!;
    const hi = appliesAtLevel(withControls, 'high');
    expect(hi.applies).toBe(true);
    expect(hi.source).toBe('derived-rev5');

    const noControls = loadRequirements().find((r) => (r.controls?.length ?? 0) === 0 && r.levels?.high?.source !== '20x-machine-readable');
    if (noControls) {
      const hp = appliesAtLevel(noControls, 'high');
      expect(hp.applies).toBe(false);
      expect(hp.source).toBe('derived-rev5-pending');
    }
  });
});

describe('bizdays', () => {
  it('skips weekends and federal holidays', () => {
    // 2026-07-04 is Independence Day (Sat) → observed Fri 2026-07-03.
    expect(usFederalHolidays(2026).has('2026-07-03')).toBe(true);
    // 2026-01-01 New Year's Day (Thu) is a holiday.
    expect(isBusinessDay(new Date('2026-01-01T12:00:00Z'))).toBe(false);
    // A normal Wednesday.
    expect(isBusinessDay(new Date('2026-01-07T12:00:00Z'))).toBe(true);
  });

  it('adds business days across a weekend', () => {
    // Fri 2026-01-09 + 1 business day = Mon 2026-01-12.
    const r = addBusinessDays(new Date('2026-01-09T00:00:00Z'), 1);
    expect(r.toISOString().slice(0, 10)).toBe('2026-01-12');
  });

  it('flags an overdue deadline', () => {
    const st = deadlineStatus('2026-01-01T00:00:00Z', { calendarDays: 14 }, '2026-02-01T00:00:00Z');
    expect(st.overdue).toBe(true);
    expect(st.days_past_due).toBeGreaterThan(0);
  });

  it('reports time remaining when within window', () => {
    const st = deadlineStatus('2026-01-01T00:00:00Z', { calendarDays: 30 }, '2026-01-10T00:00:00Z');
    expect(st.overdue).toBe(false);
    expect(st.days_past_due).toBeLessThan(0);
  });
});

describe('process-artifact-tracker', () => {
  const frr = () => getRequirement('VDR-CSO-DOC') ?? getRequirement('SCG-CSO-RSC')!;
  const ctxBase = { tier: 'moderate' as const, runId: 'r1', frmrVersion: 'v', nowIso: '2026-05-01T00:00:00Z' };

  it('emits a schema-valid PROCESS evidence file', () => {
    const ev = buildProcessArtifactEvidence(frr(), ctxBase);
    expect(ev.scope).toBe('PROCESS');
    expect(ev.impact_level).toBe('moderate');
    const v = validateEvidenceFile(JSON.parse(JSON.stringify(ev)));
    expect(v.valid, JSON.stringify(v.errors)).toBe(true);
  });

  it('fails (gap) when there is no attestation', () => {
    const ev = buildProcessArtifactEvidence(frr(), ctxBase);
    expect(ev.rollup.pass).toBe(false);
    expect(ev.providers[0]!.findings[0]!.gap).toBeTruthy();
  });

  it('passes when a fresh attestation is recorded', () => {
    const req = frr();
    const ev = buildProcessArtifactEvidence(req, {
      ...ctxBase,
      attestations: { [req.id]: { requirement_id: req.id, artifact_url: 'https://trust.example/doc', attested_by: 'CISO', attested_at: '2026-04-01T00:00:00Z' } },
    });
    expect(ev.rollup.pass).toBe(true);
    expect(ev.providers[0]!.findings[0]!.passed).toBe(true);
  });

  it('treats a stale (expired) attestation as a gap', () => {
    const req = frr();
    const ev = buildProcessArtifactEvidence(req, {
      ...ctxBase,
      attestations: { [req.id]: { requirement_id: req.id, artifact_url: 'https://x', attested_at: '2026-01-01T00:00:00Z', expires_at: '2026-03-01T00:00:00Z' } },
    });
    expect(ev.rollup.pass).toBe(false);
  });

  it('marks FedRAMP/agency-actor requirements as awareness-only and passes them', () => {
    const awareness = loadRequirements().find((r) => actorScopeOf(r) !== 'provider')!;
    const ev = buildProcessArtifactEvidence(awareness, ctxBase);
    expect(ev.awareness_only).toBe(true);
    expect(ev.rollup.pass).toBe(true);
    expect(ev.actor_scope).not.toBe('provider');
  });
});
