/**
 * LOOP-B.B5 — Organisational-risk reader tests.
 *
 * pullOrganisationalRisks() GETs the tracker (mocked at the wire layer per
 * CLAUDE.md Rule 2.4) and writes a signed out/.organisational-risks.json
 * snapshot; loadCachedOrganisationalRisks() reads it with no network. A tracker
 * outage leaves the register with only finding + acceptance entries — never a
 * fabricated organisational risk (REO Rule 4).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import {
  pullOrganisationalRisks,
  loadCachedOrganisationalRisks,
  ORGANISATIONAL_RISKS_SNAPSHOT,
  type PulledOrganisationalRisk,
} from '../../core/organisational-risk-reader.ts';
import { verifyDetached } from '../../core/sign.ts';

const NOW = new Date('2026-07-02T12:00:00.000Z');

function mkOrg(over: Partial<PulledOrganisationalRisk> = {}): PulledOrganisationalRisk {
  return {
    uuid: 'org-1', title: 'Key vendor bankruptcy', description: 'x'.repeat(120), category: 'third-party',
    likelihood: 'moderate', impact: 'high', inherent_risk: 'moderate', residual_risk: 'low', treatment: 'transfer',
    owner: 'CISO', review_date: '2026-12-31T00:00:00.000Z', nist_control_ids: ['sa-9'], compensating_control_uuids: null,
    status: 'open', closed_at: null, created_at: '2026-06-01T00:00:00.000Z', updated_at: '2026-06-01T00:00:00.000Z', ...over,
  };
}

function jsonResponse(body: unknown) {
  return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
}

describe('organisational-risk reader', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(resolve(tmpdir(), 'org-')); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('pullOrganisationalRisks writes a signed .organisational-risks.json snapshot', async () => {
    const items = [mkOrg(), mkOrg({ uuid: 'org-2', category: 'supply-chain' })];
    const calls: string[] = [];
    const fetchImpl = async (url: string) => { calls.push(url); return jsonResponse({ items }); };
    const pulled = await pullOrganisationalRisks('http://tracker.local/', 'tok', dir, { fetchImpl, now: () => NOW });

    expect(pulled).toHaveLength(2);
    expect(calls[0]).toBe('http://tracker.local/api/organisational-risks');
    const p = resolve(dir, ORGANISATIONAL_RISKS_SNAPSHOT);
    expect(existsSync(p)).toBe(true);
    const doc = JSON.parse(readFileSync(p, 'utf8'));
    expect(doc.items).toHaveLength(2);
    expect(doc.provenance.emitter).toBe('core/organisational-risk-reader.ts');
    // The snapshot is signed by core/sign.ts over its canonical bytes with the
    // signature undefined AND signingKeyId blank (both are set only after signing),
    // mirroring the B.B3/B.B4 reader snapshots.
    const { signature } = doc;
    const { canonicalize } = await import('../../core/sign.ts');
    const canonical = canonicalize({ ...doc, provenance: { ...doc.provenance, signingKeyId: '' }, signature: undefined });
    expect(verifyDetached(Buffer.from(canonical, 'utf8'), signature)).toBe(true);

    // The cached loader reads it back without network.
    const cached = loadCachedOrganisationalRisks(dir);
    expect(cached.map((r) => r.uuid)).toEqual(['org-1', 'org-2']);
  });

  it('handles tracker unavailable gracefully — cached loader returns empty list', () => {
    // No snapshot on disk → empty list (register omits organisational entries),
    // logged as organisational-risk:missing-snapshot — never fabricated.
    expect(loadCachedOrganisationalRisks(dir)).toEqual([]);
    expect(existsSync(resolve(dir, ORGANISATIONAL_RISKS_SNAPSHOT))).toBe(false);
  });
});
