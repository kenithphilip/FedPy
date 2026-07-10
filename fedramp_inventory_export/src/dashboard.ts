/**
 * Executive Summary dashboard model — the leadership-facing top sheet.
 *
 * A structured layout (KPI tiles + posture bars + top-risk lists) rather than a
 * flat table; the writer renders it with section bands, big KPI cells, and
 * severity colour. Pure — derived entirely from the JoinResult.
 */
import type { JoinResult, FlatFinding } from './join.ts';
import { assetFamily } from './tables.ts';
import { LEVERS, LEVER_ORDER, leverForFinding } from './remediation.ts';

export interface Kpi { label: string; value: string; tone: 'good' | 'warn' | 'bad' | 'neutral'; note?: string; }

export interface DashboardModel {
  title: string;
  subtitle: string;
  generatedAt: string;
  account: string;
  kpis: Kpi[];
  /** Posture rows: [label, satisfied, partial, notSatisfied, notAssessed]. */
  controlPosture: Array<{ framework: string; satisfied: number; partial: number; notSatisfied: number; notAssessed: number; inScope: number; assessedPassRate: number }>;
  /** Severity breakdown of failing findings. */
  severity: { critical: number; high: number; medium: number; low: number };
  /** Top remediation levers by finding count (deploy priorities). */
  topLevers: Array<{ lever: string; findings: number; critical: number; high: number; owner: string }>;
  /** Family posture: highest non-compliant first. */
  familyPosture: Array<{ family: string; assets: number; nonCompliant: number }>;
  /** Caveats / how-to-read notes. */
  notes: string[];
}

export function buildDashboard(join: JoinResult, opts: { account: string; generatedAt: string }): DashboardModel {
  const s = join.summary;
  const fails = join.findings.filter((f) => !f.passed && !f.awarenessOnly);

  const severity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of fails) {
    if (f.severity === 'critical') severity.critical++;
    else if (f.severity === 'high') severity.high++;
    else if (f.severity === 'medium') severity.medium++;
    else if (f.severity === 'low') severity.low++;
  }

  // Top levers by finding count.
  const leverAgg = new Map<string, { findings: number; critical: number; high: number }>();
  for (const f of fails) {
    const k = leverForFinding(f);
    let a = leverAgg.get(k);
    if (!a) { a = { findings: 0, critical: 0, high: 0 }; leverAgg.set(k, a); }
    a.findings++;
    if (f.severity === 'critical') a.critical++;
    else if (f.severity === 'high') a.high++;
  }
  const topLevers = [...leverAgg.entries()]
    .sort((a, b) => b[1].critical - a[1].critical || b[1].high - a[1].high || b[1].findings - a[1].findings ||
      LEVER_ORDER.indexOf(a[0]) - LEVER_ORDER.indexOf(b[0]))
    .slice(0, 8)
    .map(([k, a]) => ({ lever: LEVERS[k]!.name, findings: a.findings, critical: a.critical, high: a.high, owner: LEVERS[k]!.defaultOwner }));

  // Family posture (non-compliant desc).
  const famAgg = new Map<string, { assets: number; nonCompliant: number }>();
  for (const ac of join.assetCompliance) {
    const fam = assetFamily(ac.asset);
    let a = famAgg.get(fam);
    if (!a) { a = { assets: 0, nonCompliant: 0 }; famAgg.set(fam, a); }
    a.assets++;
    if (ac.status === 'non-compliant') a.nonCompliant++;
  }
  const familyPosture = [...famAgg.entries()]
    .map(([family, a]) => ({ family, assets: a.assets, nonCompliant: a.nonCompliant }))
    .sort((a, b) => b.nonCompliant - a.nonCompliant || b.assets - a.assets || a.family.localeCompare(b.family));

  const pctS = (n: number) => `${(n * 100).toFixed(0)}%`;
  const kpis: Kpi[] = [
    { label: 'Assets Inventoried', value: String(s.assetCount), tone: 'neutral' },
    { label: 'Non-Compliant Assets', value: String(s.assetsNonCompliant), tone: s.assetsNonCompliant > 0 ? 'bad' : 'good', note: `${s.assetsNotAssessed} not-assessed` },
    { label: 'Requirements Not Met', value: `${s.requirementsNotMet}`, tone: s.requirementsNotMet > 0 ? 'bad' : 'good', note: `${s.requirementsMet} met · ${s.requirementsPartial} partial` },
    { label: 'Open Findings', value: String(s.findingsFailing), tone: s.findingsFailing > 0 ? 'bad' : 'good', note: `${severity.critical} critical · ${severity.high} high` },
    { label: 'Rev5 Moderate Coverage', value: pctS(s.rev5.baselineCoverageRate), tone: s.rev5.baselineCoverageRate >= 0.5 ? 'warn' : 'bad', note: `${s.rev5.satisfied}/${s.rev5.inScope} controls satisfied` },
    { label: '20x Assessed Pass Rate', value: pctS(s.twentyX.assessedPassRate), tone: s.twentyX.assessedPassRate >= 0.5 ? 'warn' : 'bad', note: `${s.twentyX.satisfied}/${s.twentyX.inScope} of 20x-referenced controls` },
  ];

  return {
    title: 'FedRAMP 20x / Rev5 — Cloud Security Posture',
    subtitle: 'Executive Summary (Impact level: Moderate)',
    generatedAt: opts.generatedAt,
    account: opts.account,
    kpis,
    controlPosture: [
      { framework: 'NIST 800-53 Rev5 (Moderate baseline)', satisfied: s.rev5.satisfied, partial: s.rev5.partiallySatisfied, notSatisfied: s.rev5.notSatisfied, notAssessed: s.rev5.notAssessed, inScope: s.rev5.inScope, assessedPassRate: s.rev5.assessedPassRate },
      { framework: 'FedRAMP 20x (referenced controls)', satisfied: s.twentyX.satisfied, partial: s.twentyX.partiallySatisfied, notSatisfied: s.twentyX.notSatisfied, notAssessed: s.twentyX.notAssessed, inScope: s.twentyX.inScope, assessedPassRate: s.twentyX.assessedPassRate },
    ],
    severity,
    topLevers,
    familyPosture,
    notes: [
      'Compliance status is an automated ASSESSMENT AID from read-only cloud evidence — not a formal 3PAO determination.',
      '"Not-assessed" = no automated evidence names the asset/control this run; it is NOT asserted compliant.',
      'Use the Remediation Plan sheet (grouped by security lever) to drive tool deployment; Cluster / Grouping Summary shows where gaps concentrate.',
      'Awareness-only requirements (obligate FedRAMP / agency / 3PAO) are excluded from the provider pass/fail counts.',
    ],
  };
}
