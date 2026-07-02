/**
 * LOOP-B.B3 — Risk-acceptance expiry enforcer.
 *
 * FedRAMP requires risk acceptances to carry a bounded expiration (annual review
 * at most). This background task transitions approved acceptances whose
 * expiration_date has passed to status='expired' and writes an audit_log row per
 * transition, so the tracker + the cloud-evidence POA&M emitter stop treating
 * them as active deviations.
 *
 * Defence-in-depth: the cloud-evidence reader's activeAcceptanceFor() ALSO
 * filters expiration_date>now(), so an acceptance never propagates to OSCAL past
 * its expiry even if the enforcer hasn't run yet (e.g. server was down). This
 * task keeps the DB state honest for the tracker UI + audit trail.
 */
import type { Database } from 'better-sqlite3';
import { db } from './db.ts';

const HOUR_MS = 60 * 60 * 1000;

/**
 * Scan for approved acceptances past their expiration_date, flip them to
 * 'expired', and audit each. Returns the number of rows expired. `nowIso`
 * is injectable for deterministic tests.
 */
export function runOnce(conn: Database = db(), nowIso: string = new Date().toISOString()): number {
  const expired = conn.prepare(
    `SELECT id, uuid, finding_uuid FROM risk_acceptances WHERE status = 'approved' AND expiration_date < ?`,
  ).all(nowIso) as Array<{ id: number; uuid: string; finding_uuid: string }>;
  for (const row of expired) {
    conn.prepare(`UPDATE risk_acceptances SET status = 'expired' WHERE id = ?`).run(row.id);
    conn.prepare(
      `INSERT INTO audit_log (user_id, item_id, item_type, field, old_value, new_value)
       VALUES (NULL, ?, 'risk_acceptance', 'expired', 'approved', 'expired')`,
    ).run(`acceptance:${row.uuid}`);
  }
  return expired.length;
}

/**
 * Boot the enforcer: run once immediately, then hourly. Returns the interval
 * handle (the caller may clear it on shutdown). Called from server/index.ts.
 */
export function startRiskAcceptanceEnforcer(): NodeJS.Timeout {
  runOnce();
  const handle = setInterval(() => runOnce(), HOUR_MS);
  // Don't keep the event loop alive solely for the enforcer.
  if (typeof handle.unref === 'function') handle.unref();
  return handle;
}
