/**
 * Monthly POA&M delta workflow — LOOP-E.E2.
 *
 * Wraps the LOOP-A.A1 OSCAL POA&M emitter (`emitOscalPoam`) with the cross-month
 * layer the FedRAMP Rev5 ConMon cadence requires:
 *
 *   1. Load the prior month's POA&M from the ledger + archive (core/poam-ledger.ts).
 *   2. Thread `metadata.revisions[]` forward — the prior month becomes a revision
 *      entry, so any single re-emitted POA&M carries the full version chain a
 *      3PAO needs to reconstruct lineage (OSCAL v1.1.2 metadata.revisions).
 *   3. Re-emit the full OSCAL POA&M (via emitOscalPoam, with the threaded history).
 *   4. Compute a month-over-month delta keyed on deterministic poam-item UUIDs
 *      (the A.A1 deterministicUuid() pattern makes the same finding map to the
 *      same uuid month-over-month — this is exactly what makes the diff possible).
 *   5. Render `poam-delta-<YYYY-MM>.md` for operator review before the monthly
 *      USDA Connect.gov upload.
 *   6. Archive the just-emitted document to `archive/poam-<YYYY-MM>.json` and
 *      append a ledger line.
 *
 * Sources (verbatim, per docs/slices/E/E.E2.md §2):
 *   - OSCAL v1.1.2 POA&M JSON reference (metadata.revisions[] cardinality).
 *   - FedRAMP Rev5 ConMon Overview: "Each month, the CSP uploads an up-to-date
 *     POA&M and inventory …".
 *   - NIST SP 800-53 Rev5 CA-5: "Update existing plan of action and milestones
 *     [Assignment: organization-defined frequency] …".
 *
 * REO compliance (cloud-evidence/CLAUDE.md):
 *   - The delta is derived ENTIRELY from two real OSCAL POA&M documents (the
 *     archived prior + the freshly-emitted current). There is no shadow diff DB.
 *   - poam-item UUIDs are the diff key; they are deterministic + traceable.
 *   - When there are zero failing findings, emitOscalPoam returns a structured
 *     skip; this workflow propagates it WITHOUT writing an archive, delta, or
 *     ledger line (no fabricated "empty" month).
 *   - First month of operation renders a real true statement, not a marker.
 *   - A corrupt / tampered prior archive raises a typed error (see poam-ledger.ts)
 *     — never silently treated as "first month".
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  emitOscalPoam,
  extractRevisionEntries,
  type OscalPoam,
  type OscalPoamItem,
  type OscalPoamDocument,
  type RevisionEntry,
  type PoamEmitOptions,
  type PoamEmitResult,
} from './oscal-poam.ts';
import type { Severity } from './envelope.ts';
import type { KevEntry } from './kev-feed.ts';
import {
  appendPoamLedger,
  loadPriorMonthPoam,
  poamArchiveRelPath,
  sha256Hex,
  POAM_ARCHIVE_DIR,
  type PoamLedgerEntry,
} from './poam-ledger.ts';

const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const FIRST_MONTH_STATEMENT = 'First month of ConMon operation; no prior POA&M to compare against.';

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Thrown when reportMonth is not a strict YYYY-MM string. */
export class InvalidPoamMonthError extends Error {
  constructor(month: string) {
    super(`Invalid POA&M report month "${month}": expected YYYY-MM (e.g. 2026-07).`);
    this.name = 'InvalidPoamMonthError';
  }
}

// ─── Delta shape ──────────────────────────────────────────────────────────────

export interface PoamItemRef {
  uuid: string;
  title: string;
  severity: string;
  status: string;
  ksi_id: string | null;
  rule: string | null;
  deadline: string | null;
}

export interface StatusChange {
  uuid: string;
  title: string;
  prev_status: string;
  new_status: string;
  ksi_id: string | null;
}

export interface SeverityChange {
  uuid: string;
  title: string;
  prev: string;
  new: string;
  ksi_id: string | null;
}

export interface PastDeadlineRef extends PoamItemRef {
  days_past_deadline: number;
}

export interface PoamDelta {
  report_month: string;
  prior_month?: string;
  added: PoamItemRef[];
  closed: PoamItemRef[];
  status_changed: StatusChange[];
  severity_changed: SeverityChange[];
  past_deadline_items: PastDeadlineRef[];
}

// ─── Item view (resolve props + linked risk) ──────────────────────────────────

interface ItemView extends PoamItemRef {}

function prop(item: OscalPoamItem, name: string): string | null {
  return item.props?.find((p) => p.name === name)?.value ?? null;
}

/**
 * Resolve a poam-item to a flat view: severity + ksi + rule from props, status +
 * deadline from the linked risk (falling back to the item's own
 * `remediation-deadline` prop for supply-chain items, which carry no risk).
 */
function viewItem(doc: OscalPoam, item: OscalPoamItem): ItemView {
  const riskUuid = item['related-risks']?.[0]?.['risk-uuid'];
  const risk = riskUuid ? doc.risks?.find((r) => r.uuid === riskUuid) : undefined;
  return {
    uuid: item.uuid,
    title: item.title,
    severity: prop(item, 'severity') ?? 'info',
    status: risk?.status ?? 'open',
    ksi_id: prop(item, 'ksi-id'),
    rule: prop(item, 'rule'),
    deadline: risk?.deadline ?? prop(item, 'remediation-deadline'),
  };
}

function byUuid(views: ItemView[]): Map<string, ItemView> {
  const m = new Map<string, ItemView>();
  for (const v of views) m.set(v.uuid, v);
  return m;
}

function sortRefs<T extends PoamItemRef>(refs: T[]): T[] {
  return refs.sort((a, b) => {
    const ra = SEVERITY_RANK[a.severity] ?? 99;
    const rb = SEVERITY_RANK[b.severity] ?? 99;
    if (ra !== rb) return ra - rb;
    return (a.ksi_id ?? '').localeCompare(b.ksi_id ?? '')
      || (a.rule ?? '').localeCompare(b.rule ?? '')
      || a.uuid.localeCompare(b.uuid);
  });
}

function daysBetween(fromIso: string, to: Date): number {
  const from = new Date(fromIso).getTime();
  return Math.floor((to.getTime() - from) / 86_400_000);
}

/**
 * Compute the month-over-month delta between a prior POA&M (or null for the first
 * month) and the current one. `past_deadline_items` are evaluated against the
 * current document's metadata.last-modified time (deterministic — Q3), counting
 * any non-closed item whose deadline has elapsed.
 */
export function computePoamDelta(
  prior: OscalPoam | null,
  current: OscalPoam,
  reportMonth: string,
  priorMonth?: string,
): PoamDelta {
  const nowIso = current.metadata['last-modified'];
  const now = new Date(nowIso);

  const curViews = current['poam-items'].map((i) => viewItem(current, i));
  const priorViews = prior ? prior['poam-items'].map((i) => viewItem(prior, i)) : [];
  const curMap = byUuid(curViews);
  const priorMap = byUuid(priorViews);

  const added: PoamItemRef[] = [];
  const closed: PoamItemRef[] = [];
  const statusChanged: StatusChange[] = [];
  const severityChanged: SeverityChange[] = [];

  if (prior) {
    for (const v of curViews) if (!priorMap.has(v.uuid)) added.push(v);
    for (const v of priorViews) if (!curMap.has(v.uuid)) closed.push(v);
    for (const cur of curViews) {
      const prev = priorMap.get(cur.uuid);
      if (!prev) continue;
      if (prev.status !== cur.status) {
        statusChanged.push({ uuid: cur.uuid, title: cur.title, prev_status: prev.status, new_status: cur.status, ksi_id: cur.ksi_id });
      }
      if (prev.severity !== cur.severity) {
        severityChanged.push({ uuid: cur.uuid, title: cur.title, prev: prev.severity, new: cur.severity, ksi_id: cur.ksi_id });
      }
    }
  }

  const pastDeadline: PastDeadlineRef[] = [];
  for (const v of curViews) {
    if (!v.deadline || v.status === 'closed') continue;
    const days = daysBetween(v.deadline, now);
    if (days > 0) pastDeadline.push({ ...v, days_past_deadline: days });
  }

  const delta: PoamDelta = {
    report_month: reportMonth,
    added: sortRefs(added),
    closed: sortRefs(closed),
    status_changed: statusChanged.sort((a, b) => (a.ksi_id ?? '').localeCompare(b.ksi_id ?? '') || a.uuid.localeCompare(b.uuid)),
    severity_changed: severityChanged.sort((a, b) => (a.ksi_id ?? '').localeCompare(b.ksi_id ?? '') || a.uuid.localeCompare(b.uuid)),
    past_deadline_items: sortRefs(pastDeadline) as PastDeadlineRef[],
  };
  if (priorMonth) delta.prior_month = priorMonth;
  return delta;
}

// ─── Markdown rendering ───────────────────────────────────────────────────────

function mdTable(headers: string[], rows: string[][]): string {
  const head = `| ${headers.join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.map((r) => `| ${r.join(' | ')} |`).join('\n');
  return rows.length ? `${head}\n${sep}\n${body}` : `${head}\n${sep}`;
}

function cell(v: string | number | null | undefined): string {
  if (v === null || v === undefined || v === '') return '—';
  return String(v).replace(/\|/g, '\\|');
}

export interface PoamDeltaHeader {
  systemName?: string;
  systemId?: string;
  runId: string;
  frmrVersion: string;
  signedManifestHref?: string;
}

/** Render the operator-facing Markdown delta (6 sections per E.E2.md §6 step 3). */
export function renderPoamDeltaMarkdown(delta: PoamDelta, header: PoamDeltaHeader): string {
  const lines: string[] = [];
  lines.push(`# Monthly POA&M Delta — ${delta.report_month}`);
  lines.push('');
  // Section 1 — Header / provenance.
  lines.push(mdTable(['Field', 'Value'], [
    ['System', cell(header.systemName)],
    ['System ID', cell(header.systemId)],
    ['Report month', cell(delta.report_month)],
    ['Prior month', cell(delta.prior_month ?? null)],
    ['Tool', cell(TOOL_NAME)],
    ['Run id', cell(header.runId)],
    ['FRMR version', cell(header.frmrVersion)],
    ['Signed manifest', cell(header.signedManifestHref ?? null)],
  ]));
  lines.push('');
  if (!delta.prior_month) {
    lines.push(FIRST_MONTH_STATEMENT);
    lines.push('');
  }
  // Section 2 — Summary counts.
  lines.push('## Summary');
  lines.push('');
  lines.push(mdTable(['Metric', 'Count'], [
    ['Added items', String(delta.added.length)],
    ['Closed items', String(delta.closed.length)],
    ['Status changes', String(delta.status_changed.length)],
    ['Severity changes', String(delta.severity_changed.length)],
    ['Past-deadline items', String(delta.past_deadline_items.length)],
  ]));
  lines.push('');
  // Section 3 — Added items.
  lines.push('## Added items');
  lines.push('');
  lines.push(delta.added.length
    ? mdTable(['POA&M item', 'Severity', 'Rule', 'KSI', 'Deadline'],
        delta.added.map((i) => [cell(i.uuid), cell(i.severity), cell(i.rule), cell(i.ksi_id), cell(i.deadline)]))
    : '_None._');
  lines.push('');
  // Section 4 — Closed items.
  lines.push('## Closed items');
  lines.push('');
  lines.push(delta.closed.length
    ? mdTable(['POA&M item', 'Severity', 'Rule', 'KSI'],
        delta.closed.map((i) => [cell(i.uuid), cell(i.severity), cell(i.rule), cell(i.ksi_id)]))
    : '_None._');
  lines.push('');
  // Section 5 — Status changes.
  lines.push('## Status changes');
  lines.push('');
  lines.push(delta.status_changed.length
    ? mdTable(['POA&M item', 'Previous status', 'New status', 'KSI'],
        delta.status_changed.map((s) => [cell(s.uuid), cell(s.prev_status), cell(s.new_status), cell(s.ksi_id)]))
    : '_None._');
  lines.push('');
  // Severity changes (Q1 — present for completeness).
  lines.push('## Severity changes');
  lines.push('');
  lines.push(delta.severity_changed.length
    ? mdTable(['POA&M item', 'Previous severity', 'New severity', 'KSI'],
        delta.severity_changed.map((s) => [cell(s.uuid), cell(s.prev), cell(s.new), cell(s.ksi_id)]))
    : '_None._');
  lines.push('');
  // Section 6 — Past-deadline items.
  lines.push('## Past-deadline items');
  lines.push('');
  lines.push(delta.past_deadline_items.length
    ? mdTable(['POA&M item', 'Severity', 'Deadline', 'Days past deadline', 'KSI'],
        delta.past_deadline_items.map((i) => [cell(i.uuid), cell(i.severity), cell(i.deadline), String(i.days_past_deadline), cell(i.ksi_id)]))
    : '_None._');
  lines.push('');
  return lines.join('\n');
}

// ─── Orchestrator entry point ─────────────────────────────────────────────────

export interface PoamMonthlyOptions {
  outDir: string;
  /** Report month, "YYYY-MM". */
  reportMonth: string;
  runId: string;
  frmrVersion: string;
  systemId?: string;
  systemName?: string;
  ssp?: { href: string; remarks?: string };
  signedManifestHref?: string;
  /** CISA KEV index for the LOOP-B.B2 deadline cascade (passed through to emitOscalPoam). */
  kevIndex?: Map<string, KevEntry>;
  /** Injectable clock for the ledger's appended_at timestamp (deterministic tests). */
  now?: () => Date;
}

export interface PoamMonthlyResult {
  /** Path to the re-emitted poam.json, or null when emission was skipped. */
  poamPath: string | null;
  /** Path to poam-delta-<YYYY-MM>.md, or null when skipped. */
  deltaPath: string | null;
  /** Relative archive path (archive/poam-<YYYY-MM>.json), or null when skipped. */
  archivePath: string | null;
  /** The ledger entry appended this run, or null when skipped / idempotent. */
  ledgerEntry: PoamLedgerEntry | null;
  /** The computed delta, or null when skipped. */
  delta: PoamDelta | null;
  /** Prior month compared against, or null for the first month. */
  priorMonth: string | null;
  /** Reason emission was skipped (zero failing findings). Set only when poamPath === null. */
  skipped_reason?: PoamEmitResult['skipped_reason'];
  /** The underlying emit result. */
  emit: PoamEmitResult;
}

function resolvedStatus(doc: OscalPoam, item: OscalPoamItem): string {
  const riskUuid = item['related-risks']?.[0]?.['risk-uuid'];
  const risk = riskUuid ? doc.risks?.find((r) => r.uuid === riskUuid) : undefined;
  return risk?.status ?? 'open';
}

/**
 * Run the monthly POA&M re-emission + delta workflow. Threads the prior month's
 * revision history forward, re-emits the POA&M, computes + renders the delta,
 * archives the document, and appends a ledger line — all atomically per run.
 */
export function runPoamMonthly(opts: PoamMonthlyOptions): PoamMonthlyResult {
  if (!MONTH_RE.test(opts.reportMonth)) throw new InvalidPoamMonthError(opts.reportMonth);

  // 1. Load the prior month (typed errors on a tampered / corrupt archive).
  const prior = loadPriorMonthPoam(opts.outDir, opts.reportMonth);

  // 2. Thread metadata.revisions[] forward: existing history + the prior month
  //    promoted to a revision entry.
  let revisionsHistory: RevisionEntry[] | undefined;
  if (prior) {
    const priorAsRevision: RevisionEntry = {
      title: `POA&M ${prior.entry.report_month}`,
      'last-modified': prior.doc.metadata['last-modified'],
      version: prior.doc.metadata.version,
      'oscal-version': prior.doc.metadata['oscal-version'],
      remarks: `Monthly POA&M revision for ${prior.entry.report_month}.`,
    };
    revisionsHistory = extractRevisionEntries(prior.doc).concat([priorAsRevision]);
  }

  // 3. Re-emit the full OSCAL POA&M with the threaded history.
  const emitOpts: PoamEmitOptions = {
    outDir: opts.outDir,
    runId: opts.runId,
    frmrVersion: opts.frmrVersion,
    systemId: opts.systemId,
    systemName: opts.systemName,
    ssp: opts.ssp,
    signedManifestHref: opts.signedManifestHref,
    kevIndex: opts.kevIndex,
    revisionsHistory,
  };
  const emit = emitOscalPoam(emitOpts);

  // Zero failing findings → propagate the skip without an archive/delta/ledger.
  if (emit.path === null) {
    return {
      poamPath: null,
      deltaPath: null,
      archivePath: null,
      ledgerEntry: null,
      delta: null,
      priorMonth: prior?.entry.report_month ?? null,
      skipped_reason: emit.skipped_reason,
      emit,
    };
  }

  // 4. Read the just-emitted document back (exact bytes for archive + sha256).
  const curBuf = readFileSync(emit.path);
  const curDoc = (JSON.parse(curBuf.toString('utf8')) as OscalPoamDocument)['plan-of-action-and-milestones'];

  // 5. Compute + render the delta.
  const delta = computePoamDelta(prior?.doc ?? null, curDoc, opts.reportMonth, prior?.entry.report_month);
  const deltaMd = renderPoamDeltaMarkdown(delta, {
    systemName: opts.systemName,
    systemId: opts.systemId,
    runId: opts.runId,
    frmrVersion: opts.frmrVersion,
    signedManifestHref: opts.signedManifestHref,
  });
  const deltaRel = `poam-delta-${opts.reportMonth}.md`;
  const deltaAbs = resolve(opts.outDir, deltaRel);
  writeFileSync(deltaAbs, deltaMd);

  // 6. Archive the document + append a ledger line.
  mkdirSync(resolve(opts.outDir, POAM_ARCHIVE_DIR), { recursive: true });
  const archiveRel = poamArchiveRelPath(opts.reportMonth);
  writeFileSync(resolve(opts.outDir, archiveRel), curBuf);

  let openCount = 0;
  let closedCount = 0;
  for (const item of curDoc['poam-items']) {
    if (resolvedStatus(curDoc, item) === 'closed') closedCount++;
    else openCount++;
  }

  const entry: PoamLedgerEntry = {
    run_id: opts.runId,
    report_month: opts.reportMonth,
    last_modified: curDoc.metadata['last-modified'],
    version: curDoc.metadata.version,
    oscal_version: curDoc.metadata['oscal-version'],
    sha256: sha256Hex(curBuf),
    path: archiveRel,
    item_count: curDoc['poam-items'].length,
    open_count: openCount,
    closed_count: closedCount,
    appended_at: (opts.now ? opts.now() : new Date()).toISOString(),
  };
  appendPoamLedger(opts.outDir, entry);

  return {
    poamPath: emit.path,
    deltaPath: deltaAbs,
    archivePath: archiveRel,
    ledgerEntry: entry,
    delta,
    priorMonth: prior?.entry.report_month ?? null,
    emit,
  };
}
