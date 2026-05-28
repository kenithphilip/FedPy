/**
 * Tests for the per-requirement playbook catalog.
 *
 * Asserts:
 *   - a representative set of requirements has a playbook,
 *   - every playbook has non-empty artifacts_required + remediation_steps,
 *   - every alternative_satisfier is shaped correctly (detected:false, signals),
 *   - any sla carries a positive business/calendar-day window,
 *   - playbookFor() resolves known ids and returns undefined for unknown ids,
 *   - SLA-bearing requirements actually encode their known windows.
 */
import { describe, it, expect } from 'vitest';
import { REQUIREMENT_PLAYBOOKS, playbookFor } from '../../core/requirement-playbooks.ts';

const REPRESENTATIVE = [
  'SCN-CSO-EVA',
  'SCN-TRF-NIP',
  'VDR-TFR-KEV',
  'VDR-TFR-MAV',
  'VDR-CSO-DET',
  'CCM-QTR-SAR',
  'CCM-OAR-AVL',
  'KSI-CED-DET',
  'KSI-CED-RGT',
  'UCM-CSX-UVM',
  'UCM-CSX-CMD',
  'ICP-CSX-IRF',
  'FSI-CSO-INB',
  'PVA-CSX-VAL',
  'SCG-CSO-RSC',
  'MAS-CSO-IIR',
  'ADS-CSX-UTC',
  'KSI-AFR-VDR',
] as const;

describe('REQUIREMENT_PLAYBOOKS', () => {
  it('covers a representative set across every process family', () => {
    for (const id of REPRESENTATIVE) {
      expect(REQUIREMENT_PLAYBOOKS, `missing playbook for ${id}`).toHaveProperty(id);
    }
  });

  it('CED is handled via the KSI-CED-* indicators', () => {
    for (const id of ['KSI-CED-DET', 'KSI-CED-RGT', 'KSI-CED-RRT', 'KSI-CED-RST']) {
      expect(REQUIREMENT_PLAYBOOKS).toHaveProperty(id);
    }
  });

  it('every entry has non-empty artifacts_required and remediation_steps', () => {
    for (const [id, pb] of Object.entries(REQUIREMENT_PLAYBOOKS)) {
      expect(Array.isArray(pb.artifacts_required), `${id} artifacts_required`).toBe(true);
      expect(pb.artifacts_required!.length, `${id} artifacts_required empty`).toBeGreaterThan(0);
      expect(Array.isArray(pb.remediation_steps), `${id} remediation_steps`).toBe(true);
      expect(pb.remediation_steps!.length, `${id} remediation_steps empty`).toBeGreaterThan(0);
      for (const step of pb.remediation_steps!) {
        expect(typeof step, `${id} step type`).toBe('string');
        expect(step.trim().length, `${id} empty step`).toBeGreaterThan(0);
      }
    }
  });

  it('alternative satisfiers are shaped for runtime detection (detected:false + signals)', () => {
    for (const [id, pb] of Object.entries(REQUIREMENT_PLAYBOOKS)) {
      for (const alt of pb.alternative_satisfiers ?? []) {
        expect(typeof alt.via, `${id} alt.via`).toBe('string');
        expect(alt.via.length, `${id} alt.via empty`).toBeGreaterThan(0);
        expect(alt.evidence_required.length, `${id} alt.evidence_required empty`).toBeGreaterThan(0);
        // Playbook satisfiers must start undetected; runtime flips them.
        expect(alt.detected, `${id} alt.detected must be false`).toBe(false);
        expect(Array.isArray(alt.detection_signals), `${id} alt.detection_signals`).toBe(true);
      }
    }
  });

  it('every sla carries a positive window or a cadence string', () => {
    for (const [id, pb] of Object.entries(REQUIREMENT_PLAYBOOKS)) {
      if (!pb.sla) continue;
      const { businessDays, calendarDays, cadence } = pb.sla;
      if (businessDays != null) {
        expect(businessDays, `${id} businessDays`).toBeGreaterThan(0);
      }
      if (calendarDays != null) {
        expect(calendarDays, `${id} calendarDays`).toBeGreaterThan(0);
      }
      // An SLA must say *something*: a numeric window and/or a cadence.
      const hasWindow = businessDays != null || calendarDays != null;
      expect(hasWindow || (typeof cadence === 'string' && cadence.length > 0), `${id} sla is empty`).toBe(true);
    }
  });

  it('nist_controls is always an array', () => {
    for (const [id, pb] of Object.entries(REQUIREMENT_PLAYBOOKS)) {
      expect(Array.isArray(pb.nist_controls), `${id} nist_controls`).toBe(true);
    }
  });

  it('encodes the known SLA windows for deadline-bearing requirements', () => {
    // SCN transformative-change notification windows (business days).
    expect(REQUIREMENT_PLAYBOOKS['SCN-TRF-NIP']!.sla?.businessDays).toBe(30);
    expect(REQUIREMENT_PLAYBOOKS['SCN-TRF-NFP']!.sla?.businessDays).toBe(10);
    expect(REQUIREMENT_PLAYBOOKS['SCN-TRF-NAF']!.sla?.businessDays).toBe(5);
    expect(REQUIREMENT_PLAYBOOKS['SCN-ADP-NTF']!.sla?.businessDays).toBe(10);
    // VDR 192-day accepted-vulnerability clock.
    expect(REQUIREMENT_PLAYBOOKS['VDR-TFR-MAV']!.sla?.calendarDays).toBe(192);
    // ICP 1-hour incident reporting (encoded as a 1-day floor for the day-based engine).
    expect(REQUIREMENT_PLAYBOOKS['ICP-CSX-IRF']!.sla?.calendarDays).toBe(1);
    // KEV is a cadence pegged to CISA per-CVE dates (no fixed numeric window).
    expect(REQUIREMENT_PLAYBOOKS['VDR-TFR-KEV']!.sla?.cadence).toBeTruthy();
    // CCM quarterly cadence.
    expect(REQUIREMENT_PLAYBOOKS['CCM-OAR-AVL']!.sla?.calendarDays).toBeGreaterThan(0);
  });

  it('counts at least 90 process-requirement playbooks', () => {
    expect(Object.keys(REQUIREMENT_PLAYBOOKS).length).toBeGreaterThanOrEqual(90);
  });
});

describe('playbookFor', () => {
  it('resolves a known requirement id', () => {
    const pb = playbookFor('VDR-TFR-KEV');
    expect(pb).toBeDefined();
    expect(pb!.artifacts_required!.length).toBeGreaterThan(0);
  });

  it('returns undefined for an unknown id', () => {
    expect(playbookFor('NOT-A-REAL-ID')).toBeUndefined();
    expect(playbookFor('')).toBeUndefined();
  });
});
