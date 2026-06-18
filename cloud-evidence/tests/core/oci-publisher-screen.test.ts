/**
 * Tests for core/oci-publisher-screen.ts (LOOP-W.W2 §8 T8/T9).
 * Fingerprint-first match, OIDC issuer registrable-domain match, subject-domain
 * match, and the honest empty result when no attestations are present.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { VendorNameNormalizer } from '../../core/vendor-name-normalizer.ts';
import { buildScreenIndex } from '../../core/prohibited-vendors-screen.ts';
import { screenOciPublishers, type OciAttestation } from '../../core/oci-publisher-screen.ts';
import { buildTestCatalog, namedEntities } from '../helpers/prohibited-vendors-screen.ts';

const fx = (p: string) => fileURLToPath(new URL(`../fixtures/prohibited-vendors/${p}`, import.meta.url));
const NOW = '2026-06-16T12:00:00.000Z';
const readDoc = (p: string) => JSON.parse(readFileSync(fx(p), 'utf8')) as OciAttestation;

function index(fingerprintOverrides?: Array<{ catalog_uid: string; fingerprints: string[] }>) {
  const catalog = buildTestCatalog(namedEntities(), NOW);
  return buildScreenIndex({ catalog, normalizer: new VendorNameNormalizer(), fingerprintOverrides });
}

describe('oci-publisher-screen', () => {
  it('T8: fingerprint-first match when the operator registered the fingerprint', () => {
    const idx = index([{ catalog_uid: 'far-52-204-25::huawei-technologies-company', fingerprints: ['sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'] }]);
    const r = screenOciPublishers({ attestations: [{ path: 'x', doc: readDoc('w2-oci-fingerprint.json') }], index: idx, discoveredAt: NOW });
    const hit = r.matches.find((m) => m.matched_by === 'fingerprint');
    expect(hit).toBeDefined();
    expect(hit!.confidence).toBe(1.0);
    expect(hit!.surface).toBe('oci-publisher');
    expect(hit!.catalog_uid).toContain('huawei');
  });

  it('does not fingerprint-match when no fingerprint is registered', () => {
    const r = screenOciPublishers({ attestations: [{ path: 'x', doc: readDoc('w2-oci-fingerprint.json') }], index: index(), discoveredAt: NOW });
    expect(r.matches.find((m) => m.matched_by === 'fingerprint')).toBeUndefined();
  });

  it('T9: OIDC issuer registrable-domain match (0.85)', () => {
    const r = screenOciPublishers({ attestations: [{ path: 'x', doc: readDoc('w2-oci-oidc-domain.json') }], index: index(), discoveredAt: NOW });
    const hit = r.matches.find((m) => m.matched_by === 'domain-registrable' && m.catalog_uid.includes('hikvision'));
    expect(hit).toBeDefined();
    expect(hit!.confidence).toBeCloseTo(0.85, 5);
    expect(hit!.confidence_band).toBe('high');
  });

  it('screens an attestation directory and counts images', () => {
    const dir = fileURLToPath(new URL('../fixtures/prohibited-vendors', import.meta.url));
    const r = screenOciPublishers({ attestationDir: dir, index: index(), discoveredAt: NOW });
    expect(r.images_screened).toBeGreaterThanOrEqual(2);
  });

  it('returns zero matches when the attestation directory is absent (no fabrication)', () => {
    const r = screenOciPublishers({ attestationDir: '/nonexistent/oci-attestations', index: index(), discoveredAt: NOW });
    expect(r.matches).toEqual([]);
    expect(r.images_screened).toBe(0);
  });
});
