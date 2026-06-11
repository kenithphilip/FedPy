/**
 * Tests for core/poam-ledger.ts — the LOOP-E.E2 append-only POA&M ledger +
 * monthly archive. Covers: append + read-back, insertion order, prior-month
 * load from the archive, the null first-month case, the typed corruption /
 * tamper errors, idempotent re-runs, and empty-line resilience.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  appendPoamLedger,
  readPoamLedger,
  loadPriorMonthPoam,
  poamArchiveRelPath,
  sha256Hex,
  POAM_LEDGER_FILENAME,
  POAM_ARCHIVE_DIR,
  PoamLedgerCorruptError,
  PoamArchiveTamperedError,
  type PoamLedgerEntry,
} from '../../core/poam-ledger.ts';
import type { OscalPoamDocument } from '../../core/oscal-poam.ts';

const dirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), 'cev-poam-ledger-'));
  dirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function makePoamDoc(month: string, version: string): OscalPoamDocument {
  return {
    'plan-of-action-and-milestones': {
      uuid: `poam-${month}`,
      metadata: {
        title: 'Acme — Plan of Action and Milestones',
        'last-modified': `${month}-30T00:00:00Z`,
        version,
        'oscal-version': '1.1.2',
      },
      'system-id': { id: 'acme-prod', 'identifier-type': 'https://ietf.org/rfc/rfc4122' },
      'poam-items': [
        { uuid: 'item-1', title: '[HIGH] KSI-IAM-MFA / root_mfa', description: 'failing', props: [{ name: 'severity', value: 'high' }] },
      ],
    },
  };
}

/** Write an archive file + return a matching ledger entry (sha computed from the bytes). */
function archiveAndEntry(out: string, month: string, version: string, runId: string): PoamLedgerEntry {
  const doc = makePoamDoc(month, version);
  const buf = Buffer.from(JSON.stringify(doc, null, 2), 'utf8');
  mkdirSync(resolve(out, POAM_ARCHIVE_DIR), { recursive: true });
  const rel = poamArchiveRelPath(month);
  writeFileSync(resolve(out, rel), buf);
  return {
    run_id: runId,
    report_month: month,
    last_modified: `${month}-30T00:00:00Z`,
    version,
    oscal_version: '1.1.2',
    sha256: sha256Hex(buf),
    path: rel,
    item_count: 1,
    open_count: 1,
    closed_count: 0,
    appended_at: `${month}-30T01:00:00Z`,
  };
}

describe('poam-ledger', () => {
  it('appends a ledger entry with sha256 + path + last_modified', () => {
    const out = tmp();
    const entry = archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun');
    appendPoamLedger(out, entry);
    const back = readPoamLedger(out);
    expect(back).toHaveLength(1);
    const e = back[0]!;
    for (const k of ['run_id', 'report_month', 'last_modified', 'version', 'oscal_version', 'sha256', 'path', 'item_count', 'open_count', 'closed_count', 'appended_at'] as const) {
      expect(e[k]).toBeDefined();
    }
    expect(e.sha256).toBe(entry.sha256);
    expect(e.path).toBe('archive/poam-2026-06.json');
    expect(e.last_modified).toBe('2026-06-30T00:00:00Z');
  });

  it('reads back appended entries in insertion order', () => {
    const out = tmp();
    appendPoamLedger(out, archiveAndEntry(out, '2026-04', 'r-apr', 'run-apr'));
    appendPoamLedger(out, archiveAndEntry(out, '2026-05', 'r-may', 'run-may'));
    appendPoamLedger(out, archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun'));
    const back = readPoamLedger(out);
    expect(back.map((e) => e.report_month)).toEqual(['2026-04', '2026-05', '2026-06']);
  });

  it('loads the prior month POA&M from archive directory', () => {
    const out = tmp();
    appendPoamLedger(out, archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun'));
    const prior = loadPriorMonthPoam(out, '2026-07');
    expect(prior).not.toBeNull();
    expect(prior!.entry.report_month).toBe('2026-06');
    expect(prior!.doc.metadata.version).toBe('r-jun');
    expect(prior!.doc['poam-items']).toHaveLength(1);
  });

  it('returns null when no prior month exists', () => {
    const out = tmp();
    expect(loadPriorMonthPoam(out, '2026-07')).toBeNull();
  });

  it('throws PoamLedgerCorruptError on malformed JSONL line', () => {
    const out = tmp();
    appendPoamLedger(out, archiveAndEntry(out, '2026-05', 'r-may', 'run-may'));
    // Append a deliberately broken second line.
    writeFileSync(resolve(out, POAM_LEDGER_FILENAME),
      readFileSync(resolve(out, POAM_LEDGER_FILENAME), 'utf8') + '{not valid json\n');
    try {
      readPoamLedger(out);
      throw new Error('expected PoamLedgerCorruptError');
    } catch (e) {
      expect(e).toBeInstanceOf(PoamLedgerCorruptError);
      expect((e as PoamLedgerCorruptError).lineNumber).toBe(2);
    }
  });

  it('throws when archived file sha256 does not match ledger entry', () => {
    const out = tmp();
    const entry = archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun');
    appendPoamLedger(out, entry);
    // Tamper the archived file AFTER recording it.
    writeFileSync(resolve(out, entry.path), '{"plan-of-action-and-milestones":{"uuid":"x","metadata":{"title":"t","last-modified":"2026-06-30T00:00:00Z","version":"r-jun","oscal-version":"1.1.2"},"poam-items":[]}}');
    expect(() => loadPriorMonthPoam(out, '2026-07')).toThrow(PoamArchiveTamperedError);
  });

  it('does not double-write a ledger entry on idempotent re-run', () => {
    const out = tmp();
    const entry = archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun');
    appendPoamLedger(out, entry);
    appendPoamLedger(out, entry); // same (run_id, report_month)
    expect(readPoamLedger(out)).toHaveLength(1);
  });

  it('readPoamLedger skips empty lines (resilient to trailing newlines)', () => {
    const out = tmp();
    appendPoamLedger(out, archiveAndEntry(out, '2026-06', 'r-jun', 'run-jun'));
    // Add blank + whitespace-only trailing lines.
    writeFileSync(resolve(out, POAM_LEDGER_FILENAME),
      readFileSync(resolve(out, POAM_LEDGER_FILENAME), 'utf8') + '\n   \n\n');
    const back = readPoamLedger(out);
    expect(back).toHaveLength(1);
    expect(back[0]!.report_month).toBe('2026-06');
  });
});
