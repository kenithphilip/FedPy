/**
 * Tests for server/risk-acceptance-enforcer.ts — expiry transitions + audit.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

let tmpDir: string;

beforeAll(() => {
  tmpDir = mkdtempSync(resolve(tmpdir(), 'tracker-raenf-'));
  process.env.DB_PATH = resolve(tmpDir, 'enforcer-test.db');
});
afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

const NOW = '2026-07-02T00:00:00.000Z';
const PAST = '2026-06-01T00:00:00.000Z';
const FUTURE = '2026-12-01T00:00:00.000Z';

async function seed(): Promise<any> {
  const { db } = await import('./db.ts');
  const d = db();
  d.prepare('DELETE FROM risk_acceptances').run();
  d.prepare('DELETE FROM audit_log').run();
  d.prepare('DELETE FROM users').run();
  d.prepare(`INSERT INTO users (id, email, name, password_hash, role) VALUES (1,'iso@x','ISO','x','iso')`).run();
  const ins = (uuid: string, status: string, exp: string) =>
    d.prepare(
      `INSERT INTO risk_acceptances (uuid, finding_uuid, poam_item_uuid, ksi_id, rule, provider,
         accepted_by_user_id, accepted_at, expiration_date, business_justification, acceptance_type,
         status, signature, signing_key_id)
       VALUES (?, 'f', 'p', 'KSI-IAM-MFA', 'r', 'aws', 1, '2026-05-01T00:00:00.000Z', ?, ?, 'risk-adjustment', ?, 'sig', 'k')`,
    ).run(uuid, exp, 'j'.repeat(100), status);
  return { d, ins };
}

beforeEach(async () => { await seed(); });

describe('risk-acceptance enforcer runOnce', () => {
  it('flips status to expired when expiration_date is past for approved rows', async () => {
    const { d, ins } = await seed();
    ins('a-expired', 'approved', PAST);
    const { runOnce } = await import('./risk-acceptance-enforcer.ts');
    const n = runOnce(d, NOW);
    expect(n).toBe(1);
    expect((d.prepare(`SELECT status FROM risk_acceptances WHERE uuid='a-expired'`).get() as any).status).toBe('expired');
  });

  it('does NOT touch pending, revoked, or future-dated approved rows', async () => {
    const { d, ins } = await seed();
    ins('a-pending', 'pending', PAST);
    ins('a-revoked', 'revoked', PAST);
    ins('a-future', 'approved', FUTURE);
    const { runOnce } = await import('./risk-acceptance-enforcer.ts');
    const n = runOnce(d, NOW);
    expect(n).toBe(0);
    expect((d.prepare(`SELECT status FROM risk_acceptances WHERE uuid='a-pending'`).get() as any).status).toBe('pending');
    expect((d.prepare(`SELECT status FROM risk_acceptances WHERE uuid='a-revoked'`).get() as any).status).toBe('revoked');
    expect((d.prepare(`SELECT status FROM risk_acceptances WHERE uuid='a-future'`).get() as any).status).toBe('approved');
  });

  it('writes an audit-log row on expiration', async () => {
    const { d, ins } = await seed();
    ins('a-audit', 'approved', PAST);
    const { runOnce } = await import('./risk-acceptance-enforcer.ts');
    runOnce(d, NOW);
    const row = d.prepare(
      `SELECT field, old_value, new_value FROM audit_log WHERE item_id='acceptance:a-audit' AND item_type='risk_acceptance'`,
    ).get() as any;
    expect(row).toBeTruthy();
    expect(row.field).toBe('expired');
    expect(row.old_value).toBe('approved');
    expect(row.new_value).toBe('expired');
  });

  it('handles an empty result set without errors', async () => {
    const { d } = await seed();
    const { runOnce } = await import('./risk-acceptance-enforcer.ts');
    expect(runOnce(d, NOW)).toBe(0);
  });
});
