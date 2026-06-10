/**
 * Tests for core/risk-config.ts — LOOP-B.B1 risk-config.yaml loader/validator.
 *
 * Covers per-slice doc §8 T20 (weights must sum to 1.0) plus loader hardening:
 * defaults, EPSS toggle, operator CVSS overrides, monotonic band validation,
 * and on-disk load from a fixture.
 */
import { describe, it, expect } from 'vitest';
import { fileURLToPath } from 'node:url';
import {
  normalizeRiskConfig,
  loadRiskConfig,
  defaultRiskConfig,
  bandForScore,
  RiskConfigError,
  DEFAULT_BANDS,
} from '../../core/risk-config.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/risk-score/${p}`, import.meta.url));

describe('normalizeRiskConfig', () => {
  it('returns documented defaults for an empty / undefined config', () => {
    const cfg = normalizeRiskConfig(undefined);
    expect(cfg.weights).toEqual({ cvss: 0.4, epss: 0.3, criticality: 0.2, exposure: 0.1 });
    expect(cfg.epssEnabled).toBe(true);
    expect(cfg.epssTtlHours).toBe(24);
    expect(cfg).toEqual(defaultRiskConfig());
  });

  it('T20: rejects weights that do not sum to 1.0 with a typed, field-pathed error', () => {
    expect(() => normalizeRiskConfig({ weights: { cvss: 0.5, epss: 0.5, criticality: 0.5, exposure: 0.5 } }))
      .toThrow(RiskConfigError);
    try {
      normalizeRiskConfig({ weights: { cvss: 0.5, epss: 0.5, criticality: 0.5, exposure: 0.5 } });
    } catch (e) {
      expect((e as RiskConfigError).field).toBe('weights');
    }
  });

  it('accepts weights within the ±0.01 tolerance', () => {
    const cfg = normalizeRiskConfig({ weights: { cvss: 0.4, epss: 0.3, criticality: 0.2, exposure: 0.105 } });
    expect(cfg.weights.exposure).toBe(0.105);
  });

  it('rejects a missing weight when the weights section is present', () => {
    expect(() => normalizeRiskConfig({ weights: { cvss: 1.0 } as any })).toThrow(/weights\.epss/);
  });

  it('honours epss.enabled=false and a custom ttl_hours', () => {
    const cfg = normalizeRiskConfig({ epss: { enabled: false, ttl_hours: 6 } });
    expect(cfg.epssEnabled).toBe(false);
    expect(cfg.epssTtlHours).toBe(6);
  });

  it('upper-cases operator CVSS vector override keys', () => {
    const cfg = normalizeRiskConfig({ cvss_vectors: { 'cve-2021-44228': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } });
    expect(cfg.operatorCvssVectors['CVE-2021-44228']).toContain('CVSS:3.1');
  });

  it('rejects non-monotonic band thresholds', () => {
    expect(() => normalizeRiskConfig({ bands: { critical: 5, high: 7, medium: 4, low: 1 } })).toThrow(/bands/);
  });
});

describe('loadRiskConfig', () => {
  it('loads + validates a valid YAML fixture from disk', () => {
    const cfg = loadRiskConfig(fx('risk-config-valid.yaml'));
    expect(cfg.weights).toEqual({ cvss: 0.5, epss: 0.2, criticality: 0.2, exposure: 0.1 });
    expect(cfg.epssEnabled).toBe(false);
    expect(cfg.epssTtlHours).toBe(12);
    expect(cfg.operatorCvssVectors['CVE-2021-44228']).toContain('CVSS:3.1');
  });

  it('throws on a bad-weights YAML fixture', () => {
    expect(() => loadRiskConfig(fx('risk-config-bad-weights.yaml'))).toThrow(RiskConfigError);
  });

  it('returns defaults when the path is undefined or missing', () => {
    expect(loadRiskConfig(undefined)).toEqual(defaultRiskConfig());
    expect(loadRiskConfig('/no/such/risk-config.yaml')).toEqual(defaultRiskConfig());
  });
});

describe('bandForScore', () => {
  it('maps composite scores to qualitative bands', () => {
    expect(bandForScore(9.84, DEFAULT_BANDS)).toBe('critical');
    expect(bandForScore(7.5, DEFAULT_BANDS)).toBe('high');
    expect(bandForScore(5.0, DEFAULT_BANDS)).toBe('medium');
    expect(bandForScore(1.0, DEFAULT_BANDS)).toBe('low');
    expect(bandForScore(0.0, DEFAULT_BANDS)).toBe('none');
  });
});
