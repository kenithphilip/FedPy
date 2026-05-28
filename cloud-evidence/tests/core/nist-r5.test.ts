/**
 * Tests for core/nist-r5.ts — Rev5 control-name enrichment (PB).
 */
import { describe, it, expect } from 'vitest';
import { controlDetails, describeControls, loadNistControls } from '../../core/nist-r5.ts';
import { buildProcessArtifactEvidence } from '../../core/process-artifact-tracker.ts';
import { getRequirement } from '../../core/requirements-registry.ts';

describe('nist-r5 control lookup', () => {
  it('loads the committed Rev5 control catalog', () => {
    const c = loadNistControls();
    expect(Object.keys(c).length).toBeGreaterThan(500);
  });

  it('resolves FRMR-style ids (incl. enhancements) to official names', () => {
    const d = controlDetails(['ra-5', 'ra-5.2', 'sc-13']);
    expect(d.find((x) => x.id === 'RA-5')?.name).toBe('Vulnerability Monitoring and Scanning');
    expect(d.find((x) => x.id === 'RA-5(2)')?.name).toBe('Update System Vulnerabilities');
    expect(d.find((x) => x.id === 'SC-13')?.family).toBe('SC');
  });

  it('does not drop unknown control ids', () => {
    const d = controlDetails(['zz-99']);
    expect(d).toHaveLength(1);
    expect(d[0]!.name).toBeNull();
    expect(d[0]!.family).toBe('ZZ');
  });

  it('describeControls renders id — name strings', () => {
    expect(describeControls(['ir-4'])).toEqual(['ir-4 — Incident Handling']);
  });
});

describe('process-artifact tracker enrichment', () => {
  it('embeds nist_control_details in the evidence observations', () => {
    const req = getRequirement('VDR-CSO-RES') ?? getRequirement('SCG-CSO-RSC')!;
    const ev = buildProcessArtifactEvidence(req, { tier: 'high', runId: 'r', frmrVersion: 'v', nowIso: '2026-05-28T00:00:00Z' });
    const obs = ev.providers[0]!.findings[0]!.current_state.observations as any;
    expect(Array.isArray(obs.nist_control_details)).toBe(true);
  });
});
