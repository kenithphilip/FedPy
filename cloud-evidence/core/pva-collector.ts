/**
 * KSI-AFR-PVA — Persistent Validation and Assessment.
 *
 * Meta-collector: synthesizes from the orchestrator's run state.
 * Produces a dedicated KSI-AFR-PVA.json file alongside the normal evidence
 * files, plus contributes to the pva-run-summary.
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { EvidenceFile, ProviderBlock, RawEvidence, Finding, AlternativeSatisfier } from './envelope.ts';
import { finding } from './findings.ts';

export interface PvaInput {
  outDir: string;          // where evidence files live
  runId: string;
  startedAt: string;
  finishedAt: string;
  frmrVersion: string;
  previousRunPath?: string; // optional previous pva-run-summary.json for drift
}

interface PvaModuleResult {
  ksi_id: string;
  rollup_pass: boolean;
  findings_count: number;
  warnings_count: number;
  collected_at: string;
  duration_ms?: number;
  /** Set when the evidence file could not be parsed (corrupt/truncated JSON). */
  parse_error?: string;
}

export function buildPvaEvidence(input: PvaInput): { evidence: EvidenceFile; runSummary: any } {
  const moduleResults: PvaModuleResult[] = [];
  const allEvidenceFiles: string[] = [];
  let totalProviders = 0;

  // Read every KSI-*.json (excluding the summary + our own pva file)
  for (const f of readdirSync(input.outDir)) {
    if (!f.startsWith('KSI-') || !f.endsWith('.json')) continue;
    if (f === 'KSI-AFR-PVA.json' || f === 'KSI-CSX-SUM-input.json') continue;
    const path = join(input.outDir, f);
    allEvidenceFiles.push(path);
    try {
      const data: EvidenceFile = JSON.parse(readFileSync(path, 'utf8'));
      let findingCount = 0;
      let warningCount = 0;
      totalProviders += data.providers.length;
      for (const p of data.providers) {
        findingCount += p.findings.length;
        warningCount += (p.warnings ?? []).length;
      }
      moduleResults.push({
        ksi_id: data.ksi_id,
        rollup_pass: data.rollup.pass,
        findings_count: findingCount,
        warnings_count: warningCount,
        collected_at: data.collected_at,
      });
    } catch (e: any) {
      // A KSI file that exists but won't parse is itself a finding — surface it
      // as a failed module with the parse error so the run summary records it.
      moduleResults.push({
        ksi_id: f.replace('.json', ''),
        rollup_pass: false,
        findings_count: 0,
        warnings_count: 1,
        collected_at: input.startedAt,
        parse_error: e?.message ?? String(e),
      });
    }
  }

  // Drift calculation against previous run
  const drift: Array<{ ksi_id: string; previous_pass: boolean; current_pass: boolean }> = [];
  if (input.previousRunPath && existsSync(input.previousRunPath)) {
    try {
      const prev = JSON.parse(readFileSync(input.previousRunPath, 'utf8'));
      const prevMap = new Map<string, boolean>();
      for (const r of prev.results ?? []) prevMap.set(r.ksi_id, !!r.rollup_pass);
      for (const r of moduleResults) {
        const prevPass = prevMap.get(r.ksi_id);
        if (prevPass !== undefined && prevPass !== r.rollup_pass) {
          drift.push({ ksi_id: r.ksi_id, previous_pass: prevPass, current_pass: r.rollup_pass });
        }
      }
    } catch { /* */ }
  }

  // ---- PVA findings ----
  const totalKsis = moduleResults.length;
  const passedKsis = moduleResults.filter((r) => r.rollup_pass).length;
  const failedKsis = totalKsis - passedKsis;
  const negativeDriftCount = drift.filter((d) => d.previous_pass && !d.current_pass).length;

  const altSatisfiers: AlternativeSatisfier[] = [
    {
      via: '3rd-party continuous compliance platform (Vanta, Drata, Paramify, SecureFrame)',
      description: 'A GRC platform may drive the persistent-validation cycle externally. Evidence is the platform\'s scan history + finding lifecycle.',
      evidence_required: ['Platform tenant + scan-history export', 'Coverage matrix showing every KSI exercised on cadence', 'Sample drift event'],
      detected: false,
      detection_signals: [],
    },
  ];

  const findings: Finding[] = [
    finding({
      rule: 'pva.collector_executed_persistently',
      passed: totalKsis >= 1,
      severity: 'critical',
      current: {
        summary: `Run ${input.runId} executed ${totalKsis} KSI collectors at ${input.startedAt}. ${passedKsis} passed, ${failedKsis} failed.`,
        observations: {
          run_id: input.runId,
          started_at: input.startedAt,
          finished_at: input.finishedAt,
          total_ksis: totalKsis,
          passed: passedKsis,
          failed: failedKsis,
          total_providers: totalProviders,
          drift_events: drift.length,
          negative_drift_count: negativeDriftCount,
          evidence_files: allEvidenceFiles.map((p) => p.split('/').pop()),
        },
      },
      target: { summary: 'PVA collector runs on a documented cadence (default daily); every CLOUD/HYBRID KSI exercised each run.', rationale: 'NIST CA-7 + FRD-PVL. Persistent validation IS the script.' },
      gap: totalKsis >= 1 ? undefined : {
        description: 'No KSI evidence files produced — collector run failed.',
        affected_resources: [],
      },
      alternative_satisfiers: altSatisfiers,
      nist_controls: ['ca-7','ca-7.6'],
    }),

    finding({
      rule: 'pva.no_negative_drift_since_previous_run',
      passed: negativeDriftCount === 0,
      severity: 'high',
      current: {
        summary: drift.length === 0
          ? (input.previousRunPath ? 'No KSI changed pass/fail state since previous run.' : 'No previous run available for drift comparison.')
          : `${drift.length} KSI(s) changed state; ${negativeDriftCount} regressed from PASS → FAIL.`,
        observations: { drift_events: drift },
      },
      target: { summary: 'No KSIs regress from PASS to FAIL between runs (negative drift). Improvements (FAIL → PASS) are tracked.', rationale: 'NIST CA-7. Drift detection is what makes validation "persistent" rather than periodic.' },
      gap: negativeDriftCount === 0 ? undefined : {
        description: 'Regression(s) detected — investigate immediately.',
        affected_resources: drift.filter((d) => d.previous_pass && !d.current_pass).map((d) => ({
          type: 'pva_drift_event', identifier: d.ksi_id, name: d.ksi_id, attributes: { previous_pass: d.previous_pass, current_pass: d.current_pass },
        })),
      },
      remediation: negativeDriftCount === 0 ? undefined : {
        summary: 'Open the per-KSI evidence file for each regressed KSI; treat its `gap` + `remediation` blocks as the action plan.',
        options: [{
          approach: 'Inspect each regressed KSI evidence file.',
          mechanism: 'process',
          owner_team: 'Security',
          cost_impact: { level: 'none', notes: 'Free.' },
          availability_impact: { level: 'none', notes: 'Investigation only.' },
          customer_visible: { level: 'none', notes: 'Internal.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per regressed KSI.' },
          steps: [
            'For each regressed KSI, open out/KSI-XXX.json.',
            'Inspect findings where passed=false; apply each remediation.options[].',
            'Re-run collector to verify.',
          ],
        }],
      },
      alternative_satisfiers: [],
      nist_controls: ['ca-7','ca-7.6'],
    }),
  ];

  const provider: ProviderBlock = {
    provider: 'aws', // arbitrary; PVA is provider-neutral
    account_id: null,
    region_set: [],
    evidence: [{
      source: 'pva-collector.synthesize',
      captured_at: new Date().toISOString(),
      data: { module_results: moduleResults, drift_events: drift },
    }],
    findings,
    warnings: [],
    ksi_level_alternatives: altSatisfiers,
  };

  const envelope: EvidenceFile = {
    ksi_id: 'KSI-AFR-PVA',
    ksi_name: 'Persistent Validation and Assessment',
    ksi_statement: 'Persistently validate, assess, and report on the effectiveness and status of security decisions and policies that are implemented within the cloud service offering in alignment with the FedRAMP 20x Persistent Validation and Assessment (PVA) process, and persistently address all related requirements and recommendations.',
    scope: 'HYBRID',
    frmr_version: input.frmrVersion,
    run_id: input.runId,
    collected_at: new Date().toISOString(),
    providers: [provider],
    rollup: {
      pass: findings.every((f) => f.passed),
      passing_findings: findings.filter((f) => f.passed).length,
      failing_findings: findings.filter((f) => !f.passed).length,
      warnings: [],
      missing_evidence: [],
      alternatives_in_play: 0,
    },
    process_artifacts_required: [
      'PVA plan document URL',
      'Sign-off log on the run summary (reviewer + timestamp)',
    ],
    nist_controls: ['ca-7','ca-7.6'],
    summary_for_llm: `Persistent validation collector ran ${totalKsis} KSIs at ${input.startedAt}. ${passedKsis} pass, ${failedKsis} fail. ${negativeDriftCount} regressions since previous run.`,
  };

  const runSummary = {
    ksi_module_results: moduleResults,
    drift_events: drift,
    negative_drift_count: negativeDriftCount,
    total_ksis: totalKsis,
    passed_ksis: passedKsis,
    failed_ksis: moduleResults.filter((r) => !r.rollup_pass).map((r) => r.ksi_id),
    parse_error_ksis: moduleResults.filter((r) => r.parse_error).map((r) => r.ksi_id),
  };

  return { evidence: envelope, runSummary };
}
