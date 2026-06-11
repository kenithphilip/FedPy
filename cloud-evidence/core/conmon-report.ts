/**
 * Monthly ConMon Analysis Report builder + disk emitter (LOOP-E.E1).
 *
 * FedRAMP requires that "Each month, the CSP uploads an up-to-date POA&M and
 * inventory, along with raw vulnerability scan files ... and reports to the
 * secure repository" (Rev5 Playbook — Continuous Monitoring Overview). The
 * codebase already emits the POA&M + inventory + KSI evidence; this module
 * produces the human-readable monthly *analysis report* the agency POC expects
 * attached to the upload — as JSON (machine record), Markdown (review), and PDF
 * (the format Connect.gov uploads commonly take).
 *
 * Pipeline:
 *   buildConmonMonthlyReport()  — pure: already-loaded snapshots -> report object.
 *   emitConmonMonthlyReport()   — reads outDir, builds, signs the JSON with a
 *                                 detached Ed25519 signature, writes .json/.md/.pdf.
 *
 * REO: every counted POA&M item / scan-coverage number / KEV exposure traces to
 * a real on-disk artifact (poam.json, inventory.json, KSI-*.json, diff-report.json,
 * scn-classification.json) or the pinned FedRAMP ConMon Playbook projection.
 * Fields that cannot be auto-derived emit the literal REQUIRES-OPERATOR-INPUT
 * sentinel (REO Rule 4); a missing source file never silently becomes a zero —
 * it records a provenance.warnings entry naming the gap (REO Rule 1.5).
 */
import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { canonicalize, signDetached, type DetachedSignature } from './sign.ts';
import type { EvidenceFile, Severity } from './envelope.ts';
import { loadKevCatalog } from './kev-feed.ts';
import { renderPdf, type PdfSection } from './conmon-pdf.ts';

/** REO Rule 4 sentinel for operator-supplied fields that are absent. */
export const TBD = 'REQUIRES-OPERATOR-INPUT';
const EMITTER = 'core/conmon-report.ts';
const TOOL_NAME = 'fedramp-20x-cloud-evidence';
const CONMON_REPORT_BASENAME = (month: string) => `conmon-monthly-${month}`;
const KSI_FILE_RE = /^KSI-[A-Za-z0-9-]+\.json$/;
const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

export type ImpactLevel = 'low' | 'moderate' | 'high';
type SeverityCounts = Record<Severity, number>;

/** Thrown when --month / reportMonth is not a strict YYYY-MM string. */
export class InvalidMonthFormatError extends Error {
  constructor(month: string) {
    super(`Invalid --month "${month}": expected YYYY-MM (e.g. 2026-07).`);
    this.name = 'InvalidMonthFormatError';
  }
}

// ─── Report shape ─────────────────────────────────────────────────────────────

export interface ConmonMonthlyReport {
  run_id: string;
  report_month: string; // YYYY-MM
  generated_at: string; // ISO 8601 (UTC, Z-suffixed)
  system: {
    name?: string;
    id?: string;
    impactLevel: ImpactLevel;
    csp: string; // operator-supplied or REQUIRES-OPERATOR-INPUT
    fedrampId: string; // operator-supplied or REQUIRES-OPERATOR-INPUT
  };
  conmon_strategy_href: string; // operator-supplied or REQUIRES-OPERATOR-INPUT
  posture: {
    ksi_pass_rate: number; // 0..1
    open_poam_count: number;
    open_by_severity: SeverityCounts;
    past_deadline_count: number;
    kev_exposure_count: number;
  };
  scan_coverage: {
    assets_total: number;
    assets_scanned: number;
    by_class: Record<string, { total: number; scanned: number }>;
    internet_reachable_compliant: boolean;
    sampling_pct: number;
  };
  poam_activity: {
    opened: number;
    closed: number;
    status_changes: number;
    past_deadline_items: Array<{ poam_id: string; days_past: number; severity: string }>;
  };
  deviation_requests: {
    submitted: number;
    approved: number;
    expiring_within_30d: Array<{ dr_id: string; expires: string }>;
  };
  scn_events: {
    significant: number;
    advisory: number;
    classifications: Array<{ change_id: string; significance: string }>;
  };
  incident_summary: Array<{ id: string; status: string; reported_to: string[] }> | typeof TBD;
  annual_cycle: {
    months_elapsed: number;
    next_assessment_due: string; // YYYY-MM-DD or REQUIRES-OPERATOR-INPUT
    ssp_last_reviewed: string | typeof TBD;
  };
  provenance: {
    emitter: typeof EMITTER;
    emittedAt: string;
    sourceCalls: string[];
    signingKeyId: string;
    tool: string;
    frmrVersion: string;
    conmonPlaybookVersion: string;
    warnings?: string[];
  };
  signature?: DetachedSignature;
}

/** Pinned FedRAMP ConMon Playbook projection (docs/fedramp-conmon-playbook.generated.json). */
export interface ConmonPlaybookPin {
  remediation_table: Record<string, number>;
  scan_cadence: Record<string, number>;
  monthly_deliverables: string[];
  playbook_version: string;
  playbook_published: string;
  sha256: string;
}

export interface ConmonReportBuildOpts {
  runId: string;
  reportMonth: string; // YYYY-MM (validated by caller / emitter)
  generatedAt: string; // ISO
  now: Date; // reference "now" for deadline + annual-cycle math (deterministic)
  system: { name?: string; id?: string; impactLevel: ImpactLevel; csp?: string; fedrampId?: string };
  samplingPct: number;
  conmonStrategyHref?: string;
  sspLastReviewed?: string;
  authorizationDate?: string; // YYYY-MM-DD anchor for annual-cycle math
  frmrVersion: string;
  playbook: ConmonPlaybookPin;
  /** Already-loaded snapshots (null when the source file was absent). */
  poam: any | null;
  envelopes: EvidenceFile[];
  inventory: any | null;
  diffReport: any | null;
  scn: any | null;
  deviationLedger: Array<{ dr_id: string; state: string; expires?: string }> | null;
  /** Uppercased CVE ids in the current CISA KEV catalog (null when absent). */
  kevCveSet: Set<string> | null;
  sourcePresence: Record<string, boolean>;
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function emptySeverity(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function readProp(holder: any, name: string): string | undefined {
  const props = holder?.props;
  if (!Array.isArray(props)) return undefined;
  const p = props.find((x: any) => x?.name === name);
  return typeof p?.value === 'string' ? p.value : undefined;
}

function daysBetween(from: Date, to: Date): number {
  return Math.floor((to.getTime() - from.getTime()) / 86_400_000);
}

// ─── Pure builder ─────────────────────────────────────────────────────────────

export function buildConmonMonthlyReport(opts: ConmonReportBuildOpts): ConmonMonthlyReport {
  if (!MONTH_RE.test(opts.reportMonth)) throw new InvalidMonthFormatError(opts.reportMonth);
  const warnings: string[] = [];
  const now = opts.now;

  // ── Posture: KSI pass-rate from envelopes ──
  const ksiTotal = opts.envelopes.length;
  const ksiPassing = opts.envelopes.filter((e) => e?.rollup?.pass === true).length;
  const ksiPassRate = ksiTotal > 0 ? ksiPassing / ksiTotal : 0;
  if (ksiTotal === 0) warnings.push('no-ksi-envelopes: ksi_pass_rate defaults to 0');

  // ── KEV exposure: CVE universe from KSI envelope finding references ∩ KEV ──
  const cveUniverse = new Set<string>();
  for (const env of opts.envelopes) {
    for (const p of env.providers ?? []) {
      for (const f of p.findings ?? []) {
        for (const ref of f.references ?? []) {
          if (ref.cve_id) cveUniverse.add(ref.cve_id.toUpperCase());
        }
      }
    }
  }
  let kevExposure = 0;
  if (opts.kevCveSet) {
    for (const cve of cveUniverse) if (opts.kevCveSet.has(cve)) kevExposure++;
  } else {
    warnings.push('cisa-kev-absent: kev_exposure_count defaults to 0');
  }

  // ── Open POA&M counts: prefer the real POA&M doc; fall back to failing findings ──
  const openBySeverity = emptySeverity();
  let openCount = 0;
  let pastDeadlineCount = 0;
  const pastDeadlineItems: Array<{ poam_id: string; days_past: number; severity: string }> = [];
  const poamRoot = opts.poam?.['plan-of-action-and-milestones'];
  const poamRisks: any[] = Array.isArray(poamRoot?.risks) ? poamRoot.risks : [];
  if (opts.poam && poamRisks.length > 0) {
    for (const risk of poamRisks) {
      if (risk?.status === 'closed') continue;
      const sev = (readProp(risk, 'severity') ?? 'info') as Severity;
      if (sev in openBySeverity) openBySeverity[sev]++;
      openCount++;
      const deadline = risk?.deadline ?? readProp(risk, 'remediation-deadline');
      if (deadline) {
        const d = new Date(deadline);
        if (!Number.isNaN(d.getTime()) && d.getTime() < now.getTime()) {
          pastDeadlineCount++;
          pastDeadlineItems.push({ poam_id: String(risk.uuid ?? 'unknown'), days_past: daysBetween(d, now), severity: sev });
        }
      }
    }
  } else {
    // No POA&M doc on disk — derive open items from KSI envelope failing
    // findings (the same evidence the POA&M is generated from). REO Rule 1.5:
    // record the gap rather than silently treating it as "0 from poam.json".
    if (!opts.poam) warnings.push('poam-json-absent: posture derived from KSI envelope failing findings');
    for (const env of opts.envelopes) {
      for (const p of env.providers ?? []) {
        for (const f of p.findings ?? []) {
          if (f.passed) continue;
          const sev = f.severity as Severity;
          if (sev in openBySeverity) openBySeverity[sev]++;
          openCount++;
        }
      }
    }
  }

  // ── Scan coverage from inventory.json ──
  const assets: any[] = Array.isArray(opts.inventory?.assets) ? opts.inventory.assets : [];
  const byClass: Record<string, { total: number; scanned: number }> = {};
  let assetsScanned = 0;
  let internetCompliant = true;
  let anyPublicUnscanned = false;
  for (const a of assets) {
    const cls = typeof a.assetType === 'string' && a.assetType ? a.assetType : 'Unclassified';
    if (!byClass[cls]) byClass[cls] = { total: 0, scanned: 0 };
    byClass[cls].total++;
    const scanned = a.inLatestScan === true;
    if (scanned) {
      assetsScanned++;
      byClass[cls].scanned++;
    }
    if (a.publicFacing === true && !scanned) anyPublicUnscanned = true;
  }
  const assetsTotal = typeof opts.inventory?.asset_count === 'number' ? opts.inventory.asset_count : assets.length;
  if (!opts.inventory) {
    warnings.push('inventory-json-absent: scan_coverage internet-reachable compliance unknown');
    internetCompliant = false;
  } else {
    internetCompliant = !anyPublicUnscanned;
  }

  // ── POA&M activity from the run-over-run diff report ──
  let opened = 0;
  let closed = 0;
  let statusChanges = 0;
  if (opts.diffReport) {
    opened = Number(opts.diffReport.new_findings_count ?? 0);
    closed = Number(opts.diffReport.fixed_count ?? 0);
    statusChanges = Number(opts.diffReport.regressed_count ?? 0);
  } else {
    warnings.push('diff-report-absent: poam_activity opened/closed default to 0');
  }

  // ── Deviation requests (E.E5 ledger; absent until that slice ships) ──
  const expiring: Array<{ dr_id: string; expires: string }> = [];
  let drSubmitted = 0;
  let drApproved = 0;
  if (opts.deviationLedger) {
    for (const e of opts.deviationLedger) {
      if (e.state === 'submitted') drSubmitted++;
      if (e.state === 'approved') drApproved++;
      if (e.expires) {
        const exp = new Date(e.expires);
        if (!Number.isNaN(exp.getTime())) {
          const days = daysBetween(now, exp);
          if (days >= 0 && days <= 30) expiring.push({ dr_id: e.dr_id, expires: e.expires });
        }
      }
    }
  } else {
    warnings.push('deviation-ledger-absent: E.E5 not yet shipped');
  }

  // ── SCN events from the classifier output ──
  let scnSignificant = 0;
  let scnAdvisory = 0;
  const scnClassifications: Array<{ change_id: string; significance: string }> = [];
  if (opts.scn) {
    scnSignificant = Number(opts.scn.totals?.significant ?? 0);
    scnAdvisory = Number(opts.scn.totals?.advisory ?? 0);
    for (const c of opts.scn.classifications ?? []) {
      scnClassifications.push({ change_id: String(c?.change?.id ?? 'unknown'), significance: String(c?.significance ?? 'unknown') });
    }
  } else {
    warnings.push('scn-classification-absent: no significant-change events for the month');
  }

  // ── Annual cycle (anchored on the operator-supplied authorization date) ──
  let monthsElapsed = 0;
  let nextAssessmentDue: string = TBD;
  if (opts.authorizationDate && /^\d{4}-\d{2}-\d{2}$/.test(opts.authorizationDate)) {
    const auth = new Date(`${opts.authorizationDate}T00:00:00Z`);
    const ry = Number(opts.reportMonth.slice(0, 4));
    const rm = Number(opts.reportMonth.slice(5, 7));
    const reportStart = new Date(Date.UTC(ry, rm - 1, 1));
    if (!Number.isNaN(auth.getTime())) {
      monthsElapsed = Math.max(
        0,
        (reportStart.getUTCFullYear() - auth.getUTCFullYear()) * 12 + (reportStart.getUTCMonth() - auth.getUTCMonth()),
      );
      let k = reportStart.getUTCFullYear() - auth.getUTCFullYear();
      let candidate = new Date(Date.UTC(auth.getUTCFullYear() + k, auth.getUTCMonth(), auth.getUTCDate()));
      if (candidate.getTime() <= reportStart.getTime()) {
        k++;
        candidate = new Date(Date.UTC(auth.getUTCFullYear() + k, auth.getUTCMonth(), auth.getUTCDate()));
      }
      nextAssessmentDue = candidate.toISOString().slice(0, 10);
    }
  } else {
    warnings.push('authorization-date-absent: annual_cycle months_elapsed/next_assessment_due unanchored');
  }

  // ── Provenance: cite every real source that was present ──
  const sourceCalls: string[] = ['docs/fedramp-conmon-playbook.generated.json'];
  for (const [name, present] of Object.entries(opts.sourcePresence)) {
    if (present) sourceCalls.push(`fs.readFileSync(${name})`);
  }

  const report: ConmonMonthlyReport = {
    run_id: opts.runId,
    report_month: opts.reportMonth,
    generated_at: opts.generatedAt,
    system: {
      name: opts.system.name,
      id: opts.system.id,
      impactLevel: opts.system.impactLevel,
      csp: opts.system.csp || TBD,
      fedrampId: opts.system.fedrampId || TBD,
    },
    conmon_strategy_href: opts.conmonStrategyHref || TBD,
    posture: {
      ksi_pass_rate: ksiPassRate,
      open_poam_count: openCount,
      open_by_severity: openBySeverity,
      past_deadline_count: pastDeadlineCount,
      kev_exposure_count: kevExposure,
    },
    scan_coverage: {
      assets_total: assetsTotal,
      assets_scanned: assetsScanned,
      by_class: byClass,
      internet_reachable_compliant: internetCompliant,
      sampling_pct: opts.samplingPct,
    },
    poam_activity: { opened, closed, status_changes: statusChanges, past_deadline_items: pastDeadlineItems },
    deviation_requests: { submitted: drSubmitted, approved: drApproved, expiring_within_30d: expiring },
    scn_events: { significant: scnSignificant, advisory: scnAdvisory, classifications: scnClassifications },
    incident_summary: TBD,
    annual_cycle: {
      months_elapsed: monthsElapsed,
      next_assessment_due: nextAssessmentDue,
      ssp_last_reviewed: opts.sspLastReviewed || TBD,
    },
    provenance: {
      emitter: EMITTER,
      emittedAt: opts.generatedAt,
      sourceCalls,
      signingKeyId: '',
      tool: TOOL_NAME,
      frmrVersion: opts.frmrVersion,
      conmonPlaybookVersion: opts.playbook.playbook_version,
      warnings: warnings.length ? warnings : undefined,
    },
  };
  return report;
}

// ─── Markdown render ──────────────────────────────────────────────────────────

function mdTable(headers: string[], rows: string[][]): string {
  const head = `| ${headers.join(' | ')} |`;
  const sep = `| ${headers.map(() => '---').join(' | ')} |`;
  const body = rows.length ? rows.map((r) => `| ${r.join(' | ')} |`).join('\n') : `| ${headers.map(() => '—').join(' | ')} |`;
  return `${head}\n${sep}\n${body}`;
}

export function renderConmonMarkdown(r: ConmonMonthlyReport): string {
  const sev = r.posture.open_by_severity;
  const lines: string[] = [];
  lines.push(`# Monthly Continuous Monitoring Analysis Report`);
  lines.push('');
  lines.push(`## 1. Header`);
  lines.push('');
  lines.push(mdTable(['Field', 'Value'], [
    ['System name', r.system.name ?? TBD],
    ['System id', r.system.id ?? TBD],
    ['Impact level', r.system.impactLevel],
    ['CSP', r.system.csp],
    ['FedRAMP package id', r.system.fedrampId],
    ['Report month', r.report_month],
    ['Generated at', r.generated_at],
    ['ConMon strategy reference', r.conmon_strategy_href],
    ['ConMon Playbook version', r.provenance.conmonPlaybookVersion],
  ]));
  lines.push('');
  lines.push(`## 2. Posture snapshot`);
  lines.push('');
  lines.push(mdTable(['Metric', 'Value'], [
    ['KSI pass rate', `${(r.posture.ksi_pass_rate * 100).toFixed(1)}%`],
    ['Open POA&M items', String(r.posture.open_poam_count)],
    ['Critical / High', `${sev.critical} / ${sev.high}`],
    ['Medium / Low / Info', `${sev.medium} / ${sev.low} / ${sev.info}`],
    ['Items past deadline', String(r.posture.past_deadline_count)],
    ['KEV exposure (unique CVEs)', String(r.posture.kev_exposure_count)],
  ]));
  lines.push('');
  lines.push(`## 3. Vulnerability scan coverage`);
  lines.push('');
  lines.push(mdTable(['Asset class', 'Total', 'Scanned'],
    Object.entries(r.scan_coverage.by_class).map(([k, v]) => [k, String(v.total), String(v.scanned)])));
  lines.push('');
  lines.push(`- Assets total / scanned: **${r.scan_coverage.assets_scanned} / ${r.scan_coverage.assets_total}**`);
  lines.push(`- Internet-reachable 100% scanned (FedRAMP MUST): **${r.scan_coverage.internet_reachable_compliant ? 'Yes' : 'No'}**`);
  lines.push(`- Internal-only sampling: **${r.scan_coverage.sampling_pct}%**`);
  lines.push('');
  lines.push(`## 4. POA&M activity`);
  lines.push('');
  lines.push(mdTable(['Activity', 'Count'], [
    ['Opened this month', String(r.poam_activity.opened)],
    ['Closed this month', String(r.poam_activity.closed)],
    ['Status changes', String(r.poam_activity.status_changes)],
  ]));
  if (r.poam_activity.past_deadline_items.length) {
    lines.push('');
    lines.push(`Past-deadline items:`);
    lines.push('');
    lines.push(mdTable(['POA&M id', 'Severity', 'Days past'],
      r.poam_activity.past_deadline_items.map((i) => [i.poam_id, i.severity, String(i.days_past)])));
  }
  lines.push('');
  lines.push(`## 5. Deviation requests`);
  lines.push('');
  lines.push(mdTable(['Metric', 'Value'], [
    ['Submitted this month', String(r.deviation_requests.submitted)],
    ['Approved this month', String(r.deviation_requests.approved)],
    ['Expiring within 30 days', String(r.deviation_requests.expiring_within_30d.length)],
  ]));
  lines.push('');
  lines.push(`## 6. Significant Change Notification (SCN) events`);
  lines.push('');
  lines.push(mdTable(['Significance', 'Count'], [
    ['Significant', String(r.scn_events.significant)],
    ['Advisory', String(r.scn_events.advisory)],
  ]));
  lines.push('');
  lines.push(`## 7. Incident summary`);
  lines.push('');
  if (r.incident_summary === TBD) {
    lines.push(`> ${TBD} — incidents are captured in the tracker (LOOP-G.G2). Until that integration ships, the operator lists this month's reportable incidents (id, status, reported-to) here before submission:`);
    lines.push('');
    lines.push('- ');
  } else {
    lines.push(mdTable(['Incident id', 'Status', 'Reported to'],
      r.incident_summary.map((i) => [i.id, i.status, i.reported_to.join('; ')])));
  }
  lines.push('');
  lines.push(`## 8. Annual cycle progress`);
  lines.push('');
  lines.push(mdTable(['Field', 'Value'], [
    ['Months elapsed in authorization year', String(r.annual_cycle.months_elapsed)],
    ['Next annual assessment due', r.annual_cycle.next_assessment_due],
    ['SSP last reviewed', r.annual_cycle.ssp_last_reviewed],
  ]));
  lines.push('');
  lines.push(`## 9. Provenance`);
  lines.push('');
  lines.push(mdTable(['Field', 'Value'], [
    ['Emitter', r.provenance.emitter],
    ['Run id', r.run_id],
    ['Tool', r.provenance.tool],
    ['FRMR version', r.provenance.frmrVersion],
    ['ConMon Playbook version', r.provenance.conmonPlaybookVersion],
    ['Signing key id', r.provenance.signingKeyId || '(signed at emit)'],
  ]));
  if (r.provenance.warnings?.length) {
    lines.push('');
    lines.push(`Warnings:`);
    for (const w of r.provenance.warnings) lines.push(`- ${w}`);
  }
  lines.push('');
  return lines.join('\n');
}

// ─── PDF render ───────────────────────────────────────────────────────────────

export function renderConmonPdfSections(r: ConmonMonthlyReport): PdfSection[] {
  const sev = r.posture.open_by_severity;
  const sections: PdfSection[] = [];
  sections.push({ kind: 'heading', text: '1. Header', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Field', 'Value'],
    rows: [
      ['System name', r.system.name ?? TBD],
      ['Impact level', r.system.impactLevel],
      ['CSP', r.system.csp],
      ['FedRAMP package id', r.system.fedrampId],
      ['Report month', r.report_month],
      ['Generated at', r.generated_at],
      ['ConMon strategy ref', r.conmon_strategy_href],
    ],
  });
  sections.push({ kind: 'heading', text: '2. Posture snapshot', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Metric', 'Value'],
    rows: [
      ['KSI pass rate', `${(r.posture.ksi_pass_rate * 100).toFixed(1)}%`],
      ['Open POA&M items', String(r.posture.open_poam_count)],
      ['Critical/High', `${sev.critical}/${sev.high}`],
      ['Medium/Low/Info', `${sev.medium}/${sev.low}/${sev.info}`],
      ['Past deadline', String(r.posture.past_deadline_count)],
      ['KEV exposure', String(r.posture.kev_exposure_count)],
    ],
  });
  sections.push({ kind: 'heading', text: '3. Vulnerability scan coverage', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Asset class', 'Total', 'Scanned'],
    rows: Object.entries(r.scan_coverage.by_class).map(([k, v]) => [k, String(v.total), String(v.scanned)]),
  });
  sections.push({
    kind: 'paragraph',
    text:
      `Assets scanned ${r.scan_coverage.assets_scanned} of ${r.scan_coverage.assets_total}. ` +
      `Internet-reachable 100% scanned (FedRAMP MUST): ${r.scan_coverage.internet_reachable_compliant ? 'Yes' : 'No'}. ` +
      `Internal-only sampling: ${r.scan_coverage.sampling_pct}%.`,
  });
  sections.push({ kind: 'heading', text: '4. POA&M activity', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Activity', 'Count'],
    rows: [
      ['Opened', String(r.poam_activity.opened)],
      ['Closed', String(r.poam_activity.closed)],
      ['Status changes', String(r.poam_activity.status_changes)],
    ],
  });
  sections.push({ kind: 'heading', text: '5. Deviation requests', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Metric', 'Value'],
    rows: [
      ['Submitted', String(r.deviation_requests.submitted)],
      ['Approved', String(r.deviation_requests.approved)],
      ['Expiring <=30d', String(r.deviation_requests.expiring_within_30d.length)],
    ],
  });
  sections.push({ kind: 'heading', text: '6. SCN events', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Significance', 'Count'],
    rows: [
      ['Significant', String(r.scn_events.significant)],
      ['Advisory', String(r.scn_events.advisory)],
    ],
  });
  sections.push({ kind: 'heading', text: '7. Incident summary', level: 2 });
  sections.push({
    kind: 'paragraph',
    text:
      r.incident_summary === TBD
        ? `${TBD}: incidents are captured in the tracker (LOOP-G.G2). The operator lists reportable incidents here before submission.`
        : r.incident_summary.map((i) => `${i.id} (${i.status}) -> ${i.reported_to.join('; ')}`).join('  '),
  });
  sections.push({ kind: 'heading', text: '8. Annual cycle progress', level: 2 });
  sections.push({
    kind: 'table',
    columns: ['Field', 'Value'],
    rows: [
      ['Months elapsed', String(r.annual_cycle.months_elapsed)],
      ['Next assessment due', r.annual_cycle.next_assessment_due],
      ['SSP last reviewed', r.annual_cycle.ssp_last_reviewed],
    ],
  });
  sections.push({ kind: 'heading', text: '9. Provenance', level: 2 });
  sections.push({
    kind: 'paragraph',
    text:
      `Emitter ${r.provenance.emitter}; run ${r.run_id}; tool ${r.provenance.tool}; ` +
      `FRMR ${r.provenance.frmrVersion}; ConMon Playbook ${r.provenance.conmonPlaybookVersion}.`,
  });
  return sections;
}

// ─── Detached signing (mirrors core/risk-score-emit.ts convention) ────────────

function serializeUnsignedCanonical(doc: ConmonMonthlyReport): string {
  const blanked = JSON.parse(
    JSON.stringify({ ...doc, provenance: { ...doc.provenance, signingKeyId: '' }, signature: undefined }),
  );
  return canonicalize(blanked);
}

function signReport(doc: ConmonMonthlyReport, outDir: string): DetachedSignature {
  const sig = signDetached(Buffer.from(serializeUnsignedCanonical(doc), 'utf8'), outDir);
  doc.provenance.signingKeyId = sig.keyId;
  doc.signature = sig;
  return sig;
}

// ─── Disk emitter ─────────────────────────────────────────────────────────────

export interface ConmonReportEmitOpts {
  outDir: string;
  runId: string;
  reportMonth: string; // YYYY-MM
  generatedAt?: string;
  now?: () => Date;
  system: { name?: string; id?: string; impactLevel?: ImpactLevel; csp?: string; fedrampId?: string };
  samplingPct?: number;
  conmonStrategyHref?: string;
  sspLastReviewed?: string;
  authorizationDate?: string;
  frmrVersion: string;
  playbookPath?: string;
  kevPath?: string;
}

export interface ConmonReportEmitResult {
  jsonPath: string;
  mdPath: string;
  pdfPath: string;
  report: ConmonMonthlyReport;
}

function readJsonIfPresent(path: string): { value: any | null; present: boolean } {
  if (!existsSync(path)) return { value: null, present: false };
  try {
    return { value: JSON.parse(readFileSync(path, 'utf8')), present: true };
  } catch {
    return { value: null, present: false };
  }
}

function loadEnvelopes(outDir: string): { envelopes: EvidenceFile[]; present: boolean } {
  let names: string[];
  try {
    names = readdirSync(outDir);
  } catch {
    return { envelopes: [], present: false };
  }
  const files = names
    .filter((f) => KSI_FILE_RE.test(f) && !f.endsWith('.signed.json') && !f.endsWith('.example.json'))
    .filter((f) => {
      try {
        return statSync(resolve(outDir, f)).isFile();
      } catch {
        return false;
      }
    })
    .sort();
  const envelopes: EvidenceFile[] = [];
  for (const f of files) {
    try {
      envelopes.push(JSON.parse(readFileSync(resolve(outDir, f), 'utf8')) as EvidenceFile);
    } catch {
      // Unreadable envelope — skip; do not fabricate.
    }
  }
  return { envelopes, present: files.length > 0 };
}

function loadDeviationLedger(outDir: string): { ledger: Array<{ dr_id: string; state: string; expires?: string }> | null } {
  const p = resolve(outDir, 'deviation-ledger.jsonl');
  if (!existsSync(p)) return { ledger: null };
  try {
    const rows = readFileSync(p, 'utf8')
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    return { ledger: rows };
  } catch {
    return { ledger: null };
  }
}

export async function emitConmonMonthlyReport(opts: ConmonReportEmitOpts): Promise<ConmonReportEmitResult> {
  if (!MONTH_RE.test(opts.reportMonth)) throw new InvalidMonthFormatError(opts.reportMonth);
  const now = opts.now ?? (() => new Date());
  const generatedAt = opts.generatedAt ?? now().toISOString();

  const playbookPath = opts.playbookPath ?? resolve(process.cwd(), 'docs/fedramp-conmon-playbook.generated.json');
  if (!existsSync(playbookPath)) {
    throw new Error(
      `conmon-report: pinned ConMon Playbook projection not found at ${playbookPath}. ` +
        `Run: node scripts/fetch-conmon-playbook.mjs`,
    );
  }
  const playbook = JSON.parse(readFileSync(playbookPath, 'utf8')) as ConmonPlaybookPin;

  const poam = readJsonIfPresent(resolve(opts.outDir, 'poam.json'));
  const inventory = readJsonIfPresent(resolve(opts.outDir, 'inventory.json'));
  const diff = readJsonIfPresent(resolve(opts.outDir, 'diff-report.json'));
  const scn = readJsonIfPresent(resolve(opts.outDir, 'scn-classification.json'));
  const { envelopes, present: envPresent } = loadEnvelopes(opts.outDir);
  const { ledger } = loadDeviationLedger(opts.outDir);

  // KEV catalog: offline-first (committed catalog / env path). Null when absent.
  const kev = await loadKevCatalog({ path: opts.kevPath });
  const kevCveSet = kev.count > 0 ? new Set<string>([...kev.byCve.keys()]) : null;

  const report = buildConmonMonthlyReport({
    runId: opts.runId,
    reportMonth: opts.reportMonth,
    generatedAt,
    now: now(),
    system: {
      name: opts.system.name,
      id: opts.system.id,
      impactLevel: opts.system.impactLevel ?? 'moderate',
      csp: opts.system.csp,
      fedrampId: opts.system.fedrampId,
    },
    samplingPct: opts.samplingPct ?? 100,
    conmonStrategyHref: opts.conmonStrategyHref,
    sspLastReviewed: opts.sspLastReviewed,
    authorizationDate: opts.authorizationDate,
    frmrVersion: opts.frmrVersion,
    playbook,
    poam: poam.value,
    envelopes,
    inventory: inventory.value,
    diffReport: diff.value,
    scn: scn.value,
    deviationLedger: ledger,
    kevCveSet,
    sourcePresence: {
      'poam.json': poam.present,
      'inventory.json': inventory.present,
      'diff-report.json': diff.present,
      'scn-classification.json': scn.present,
      'KSI-*.json': envPresent,
    },
  });

  // Sign the JSON (detached Ed25519 over the signature-blanked canonical form),
  // then render Markdown + PDF from the signed report object.
  signReport(report, opts.outDir);

  const base = CONMON_REPORT_BASENAME(opts.reportMonth);
  const jsonPath = resolve(opts.outDir, `${base}.json`);
  const mdPath = resolve(opts.outDir, `${base}.md`);
  const pdfPath = resolve(opts.outDir, `${base}.pdf`);

  writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  writeFileSync(mdPath, renderConmonMarkdown(report));
  writeFileSync(pdfPath, renderPdf(renderConmonPdfSections(report), { title: 'Monthly Continuous Monitoring Analysis Report' }));

  return { jsonPath, mdPath, pdfPath, report };
}
