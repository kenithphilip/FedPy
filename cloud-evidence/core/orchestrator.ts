/**
 * cloud-evidence orchestrator CLI.
 *
 * Usage:
 *   tsx core/orchestrator.ts                          # default: all configured providers, all supported KSIs
 *   tsx core/orchestrator.ts --providers aws          # AWS only
 *   tsx core/orchestrator.ts --ksis KSI-IAM-MFA,KSI-IAM-AAM
 *   tsx core/orchestrator.ts --out ./out
 *   tsx core/orchestrator.ts --dry-run                # plan only; no SDK calls
 *
 * The script is strictly read-only. See core/readonly-guardrail.ts.
 */
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { parse as parseYaml } from 'yaml';
import pLimit from 'p-limit';

import { KSI_MAP, SUPPORTED_KSIS } from './ksi-map.ts';
import type { KsiEntry } from './ksi-map.ts';
import { makeRollup, type EvidenceFile, type ProviderBlock, type ThirdPartyToolMatch } from './envelope.ts';
import { relatedKsisFor } from './cross-ksi.ts';
import { buildPvaEvidence } from './pva-collector.ts';
import type { ImpactTier } from './envelope.ts';
import { selectForLevel, getRequirement, appliesAtLevel, actorScopeOf, type RequirementEntry } from './requirements-registry.ts';
import { buildProcessArtifactEvidence, type AttestationRecord } from './process-artifact-tracker.ts';
import { REQUIREMENT_PLAYBOOKS } from './requirement-playbooks.ts';
import { buildFamilyRollup } from './family-rollup.ts';
import { buildControlBenchmark, type BenchmarkFramework } from './control-benchmark.ts';
import { writeInventoryWorkbook, readInventoryContext, enrichFromTags, reconcileScans, annotateWithFindings, dedupeAssets, buildInventorySnapshot, writeInventoryJson, applyTagGovernance, deriveEol, deriveEdges, applyDataClassification, applyDiagramLabelAndComments, type CloudAsset } from './inventory-workbook.ts';
import { emitInventoryCoverage, coverageSummary } from './inventory-coverage-report.ts';
import { collectAwsAssets } from '../providers/aws/inventory-assets.ts';
import { collectGcpAssets } from '../providers/gcp/inventory-assets.ts';
import { collectAzureAssets } from '../providers/azure/inventory-assets.ts';
import { discoverAzureAssets } from '../providers/azure/discover.ts';
import { whoAmIAzure } from './auth/azure.ts';
import { discoverAwsAssets } from '../providers/aws/discover.ts';
import { discoverGcpAssets } from '../providers/gcp/discover.ts';
import { readPreviousInventory, diffInventory, writeInventoryDiff, writeInventoryOscal, writeInventoryCmdb } from './inventory-emit.ts';
import { collectAwsCost, collectMacieSensitiveBuckets } from '../providers/aws/inventory-cost.ts';
import { collectAwsReferenceArch } from '../providers/aws/reference-arch.ts';
import { collectGcpReferenceArch } from '../providers/gcp/reference-arch.ts';
import { collectAzureReferenceArch } from '../providers/azure/reference-arch.ts';
import { createRunLedger, type RunLedger } from './run-ledger.ts';
import { acquireRunLock, RunLockHeldError, type RunLock } from './run-lock.ts';
import { AdaptiveLimiter } from './rate-control.ts';
import { adsUrlsFromEnv, probeAdsEndpoints, buildAdsFindings } from './ads-probe.ts';
import { reconcileMas, buildMasFindings } from './mas-reconcile.ts';
import { loadScgBaseline, compareScg, buildScgFindings } from './scg-comparator.ts';
import { buildCsxSum } from './csx-sum-aggregator.ts';
import { notifyDrift } from './notify.ts';
import { exportFindingsCsv } from './csv-export.ts';
import { generateHtmlReport } from './html-report.ts';
import { diffReport, snapshotRun } from './diff-report.ts';
import { buildScnReport, writeScnReport } from './scn-classifier.ts';
import { checkCoverage } from './coverage-check.ts';
import { pushAllToParamify } from './paramify-push.ts';
import { pushAllToTracker, pushRunTelemetry } from './tracker-push.ts';
import { validateEvidenceFile, formatErrors } from './schema.ts';
import { signRun, verifyRun } from './sign.ts';
import { timestampManifest } from './timestamp.ts';
import { emitOscalAssessmentResults } from './oscal.ts';
import { emitOscalSsp } from './oscal-ssp.ts';
import { emitOscalPoam, type PoamEmitResult } from './oscal-poam.ts';
import { pullActiveAcceptances } from './risk-acceptance-reader.ts';
import { pullCompensatingControls } from './compensating-control-reader.ts';
import { pullOrganisationalRisks } from './organisational-risk-reader.ts';
import { emitRiskRegister } from './risk-register.ts';
import { runPoamMonthly, type PoamMonthlyResult } from './poam-monthly.ts';
import { emitOscalAp } from './oscal-ap.ts';
import { emitSubmissionBundle } from './submission-bundle.ts';
import { emitRoeDocx } from './roe-emit.ts';
import { emitCmpDocx, type CmpCcbRosterEntry, type CmpTooling } from './cmp-emit.ts';
import { emitIscpDocx, type IscpTeamMember, type IscpVendorContact } from './iscp-emit.ts';
import {
  emitIscpTestAarDocx,
  type IscpTestParticipant, type IscpTestScenario, type IscpTestLessonLearned,
} from './iscp-test-aar.ts';
import {
  emitIrpDocx,
  type IrpSpecVersion, type IrpTeamMember, type IrpEscalationRule,
  type IrpExternalContact, type IrpCommunicationsPlan, type IrpClassificationLevel,
} from './irp-emit.ts';
import {
  emitIrpTestAarDocx,
  type IrpTestParticipant, type IrpTestScenario, type IrpTestLessonLearned,
} from './irp-test-aar.ts';
import { emitProhibitedVendorsCatalog } from './prohibited-vendors-catalog.ts';
import { emitProhibitedVendorsScreen } from './prohibited-vendors-screen-emit.ts';
import { emitSection8891bdReports } from './section889-1bd-reporter.ts';
import { emitSection889AnnualRep } from './section889-annual-rep.ts';
import { emitSsdfSatisfactionMatrix, type SsdfProductConfig } from './ssdf-evidence-aggregator.ts';
import { emitSsdfCommonForm } from './ssdf-common-form.ts';
import { emitSsdfMaterialChanges, type SsdfProduct } from './ssdf-material-change-detector.ts';
import { emitSsdfAiAugmentation } from './ssdf-ai-extension.ts';
import { renderAiAugmentationXlsx } from './ssdf-ai-extension-xlsx.ts';
import { emitConmonMonthlyReport } from './conmon-report.ts';
import { emitRiskScores } from './risk-score-emit.ts';
import { emitSubprocessorInventory } from './subprocessor-inventory.ts';
import { emitSupplyChainRiskRegister } from './supply-chain-risk.ts';
import { loadKevCatalog } from './kev-feed.ts';
import { emitSspDocx } from './ssp-docx.ts';
import { validateOscalFile } from './oscal-validate.ts';
import { buildCrosswalkReport } from './crosswalk.ts';
import { buildFanoutPlan, type FanoutTarget } from './aws-org-fanout.ts';
import { emitPowerpipeMod } from './powerpipe-emitter.ts';
import { buildSbomReport } from './sbom.ts';
import { detectAnomalies } from './anomaly.ts';
import { loadPlugins, summarizePluginLoad } from './plugin-loader.ts';
import { generatePrsForEvidence } from './llm-pr-generator.ts';
import {
  pushFailingFindings as pushTickets,
  gitHubIssuesDriver, jiraDriver, serviceNowDriver,
} from './ticket-push.ts';
import { pushEvidenceToSiem } from './siem-push.ts';
import { sendRunSummary, sendFailingFindings as sendFindingWebhooks } from './webhook-push.ts';
import { log, logger } from './log.ts';
import { classifyError, diagnoseAwsError, diagnoseGcpError } from './error-diagnostics.ts';
import * as aws from './auth/aws.ts';
import { whoAmIGcp } from './auth/gcp.ts';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..');

interface Args {
  providers: Array<'aws' | 'gcp' | 'azure'>;
  ksiFilter: string[] | null;
  /** FedRAMP impact tier to evaluate against. Resolved from CLI > config > 'moderate'. */
  impactLevel: ImpactTier | null;
  /**
   * NIST 800-53 control-benchmark framing. 'rev5' scores the full SP 800-53B
   * baseline for the level; '20x' scores only the controls the evaluated 20x
   * KSIs/FRRs reference. Resolved from CLI > env > '20x'.
   */
  framework: BenchmarkFramework;
  outDir: string;
  configPath: string;
  dryRun: boolean;
  htmlReport: boolean;
  csvExport: boolean;
  diffReport: boolean;
  /** When true, classify the run's diff (findings + inventory + optional proposed changes) as a FedRAMP Significant Change Notification report. */
  scn: boolean;
  /** Optional path to a JSON file of operator-proposed changes (consumed by the SCN classifier). */
  scnProposedPath: string | null;
  pushParamify: boolean;
  pushTracker: boolean;
  notifyOnDrift: boolean;
  /** When true, schema-validation errors fail the run (exit 2). Default is warn-and-continue. */
  strictSchema: boolean;
  /** Max concurrent KSI collections. Default 4 (conservative for AWS rate limits). */
  concurrency: number;
  /** Disable evidence-manifest signing. Default false (always sign). */
  noSign: boolean;
  /** Path to a public-key PEM used to assert the manifest's embedded key matches. */
  expectedPublicKey: string | null;
  /** When true, emit OSCAL Assessment Results alongside our own evidence files. */
  oscal: boolean;
  /** When true, emit a draft OSCAL System Security Plan (ssp.json) bootstrapped from evidence. */
  oscalSsp: boolean;
  /** When true, emit an OSCAL Plan of Action and Milestones (poam.json) from failing findings. */
  oscalPoam: boolean;
  /** When true, emit an OSCAL Assessment Plan (ap.json) — the SAP draft. */
  oscalAp: boolean;
  /**
   * When true (LOOP-A.A3), the AR emitter fails hard if its mandatory
   * `import-ap` href cannot be resolved to a real document (no AP co-emitted
   * AND no explicit --ap-href provided). Prevents shipping a submission
   * package with a synthetic AP anchor.
   */
  strictChain: boolean;
  /**
   * When true (LOOP-A.A4), build a signed FedRAMP 20x submission package
   * (tar.gz) bundling SSP+AP+AR+POA&M+IIW+manifest+timestamp+INDEX.json.
   */
  submissionBundle: boolean;
  /**
   * When true with submissionBundle, the bundler fails hard if any required
   * artifact is missing OR the OSCAL chain is broken. The right setting for
   * production submissions.
   */
  strictBundle: boolean;
  /**
   * When true (LOOP-A.A5), render a Rules of Engagement Word template
   * (out/roe.docx) pre-filled with system identity, boundary, IP ranges
   * from real inventory, scan windows, and escalation contacts.
   */
  roe: boolean;
  /**
   * When true (LOOP-C.C1), render a Configuration Management Plan Word
   * document (out/cmp.docx) — an 11-section CM-9 plan whose Configuration
   * Items table is auto-derived from real inventory.json (CM-8) and whose
   * Configuration Monitoring list is derived from core/ksi-map.ts. Process
   * narratives fall back to REQUIRES-OPERATOR-INPUT. Runs BEFORE signing so
   * cmp.docx is covered by the submission-bundle INDEX.json + run manifest.
   */
  cmp: boolean;
  /** §6 operator-supplied configuration change-control workflow narrative. */
  cmpApprovalNarrative: string | null;
  /** §9 operator-supplied rollback authority + criteria. */
  cmpRollbackAuthority: string | null;
  /** §8 operator-supplied change/maintenance windows. */
  cmpChangeWindows: string | null;
  /** §5 link to the CM-2 Baseline Configuration document (C.C9). */
  cmpBaselineConfigHref: string | null;
  /**
   * When true (LOOP-C.C2), render an Information System Contingency Plan Word
   * document (out/iscp.docx) — CP-2 / CP-9 / CP-10. The §4.2 Recovery-evidence
   * table is auto-filled from the real signed RPL-family KSI files; Appendix B
   * from the real subprocessor inventory; recovery narratives fall back to
   * REQUIRES-OPERATOR-INPUT. Runs BEFORE signing so iscp.docx is covered by the
   * submission bundle. Structured input comes from config.yaml:iscp.*.
   */
  iscp: boolean;
  /**
   * When true (LOOP-C.C2), render the Contingency Plan Test After-Action Report
   * (out/iscp-test-aar.docx) — CP-4. Test scenarios + lessons learned are
   * operator-supplied via config.yaml:iscp.test.*; the report anchors to the
   * ISCP under test (out/iscp.docx SHA-256) when emitted in the same run.
   */
  iscpTestAar: boolean;
  /** §4.1 Recovery Time Objective (hours) — overrides config.yaml:iscp.rto.hours. */
  iscpRtoHours: number | null;
  /** §4.1 Recovery Point Objective (hours) — overrides config.yaml:iscp.rpo.hours. */
  iscpRpoHours: number | null;
  /** AAR test date (ISO) — overrides config.yaml:iscp.test.test_date. */
  iscpTestDate: string | null;
  /** AAR test type (tabletop|functional|full-interruption) — overrides config. */
  iscpTestType: string | null;
  /**
   * When true (LOOP-C.C3), render the Incident Response Plan (out/irp.docx) —
   * IR-8 / IR-3 / IR-4 / IR-6, structured per NIST SP 800-61 Rev. 3 (CSF 2.0
   * phases). §4 Detect auto-fills from the real KSI-INR-RIR evidence; §9
   * Reporting SLAs come from the FedRAMP Incident Communications Procedures; the
   * IR-team roster + communications plan fall back to REQUIRES-OPERATOR-INPUT.
   * Runs after the ISCP emit + before signing so irp.docx is covered by the
   * submission bundle. Structured input comes from config.yaml:irp.*.
   */
  irp: boolean;
  /**
   * When true (LOOP-C.C3), render the Incident Response Test After-Action Report
   * (out/irp-test-aar.docx) — IR-3. Test scenarios + the 5-phase timing matrix +
   * lessons learned are operator-supplied via config.yaml:irp.test.*; the report
   * anchors to the IRP under test (out/irp.docx SHA-256) when emitted the same run.
   */
  irpTestAar: boolean;
  /** IR spec version (800-61r2|800-61r3, default r3) — overrides config.yaml:irp.spec_version. */
  irpSpecVersion: string | null;
  /** Optional RoE href to populate in the AP's back-matter + terms-and-conditions. */
  apRoeHref: string | null;
  /** Optional sampling-methodology href to populate in the AP's back-matter. */
  apSamplingMethodologyHref: string | null;
  /** Optional 3PAO organization name to record as a metadata party on the AP. */
  thirdPartyAssessor: string | null;
  /** When true, also render the OSCAL SSP to a Word document (ssp.docx). Implies oscalSsp. */
  sspDocx: boolean;
  /** Organization name to embed in OSCAL metadata. */
  oscalOrgName: string | null;
  /** System name to embed in the OSCAL SSP. */
  systemName: string | null;
  /** System identifier to embed in the OSCAL SSP. */
  systemId: string | null;
  /** When true, emit crosswalk-report.json mapping NIST controls to SOC2/ISO27001/HIPAA. */
  crosswalk: boolean;
  /** When true, enumerate cloud assets and emit the FedRAMP Integrated Inventory Workbook (CSV + XLSX). */
  inventoryWorkbook: boolean;
  /** When true, run ONLY the inventory (skip KSI collection + process evidence) — a fast inventory-focused run. */
  inventoryOnly: boolean;
  /** When true, audit the running env against FedRAMP reference-architecture hardening and emit AUDIT-REFARCH-{AWS,GCP}.json. */
  referenceArch: boolean;
  /** When true, fan out collection across all AWS Organizations member accounts. */
  awsOrgFanout: boolean;
  /** When fanout is on: only collect these account IDs. */
  awsFanoutInclude: string[];
  /** When fanout is on: skip these account IDs. */
  awsFanoutExclude: string[];
  /** Cross-account role name to assume in member accounts. */
  awsCrossAccountRole: string | null;
  /** When true, emit a Powerpipe mod under out/powerpipe/ for Powerpipe + Steampipe consumers. */
  powerpipe: boolean;
  /** Path to a directory of SBOM files (CycloneDX/SPDX JSON) to parse. */
  sbomDir: string | null;
  /** When true, run anomaly detection vs the rolling 7-day window. */
  anomaly: boolean;
  /** Optional directory of user-supplied plugin modules. */
  pluginsDir: string | null;
  /** When true, generate remediation PRs via Anthropic Claude for each failing finding. */
  llmGeneratePrs: boolean;
  /** Ticket provider for failing findings (none = skip). */
  ticketProvider: 'github' | 'jira' | 'servicenow' | null;
  /** SIEM HTTP intake URL (OCSF events). */
  siemUrl: string | null;
  /** Generic webhook URL. */
  webhookUrl: string | null;
  /**
   * When true (LOOP-W.W1), emit the signed prohibited-vendor catalog
   * (out/prohibited-vendors-catalog.json) merged from OFAC SDN + BIS Entity
   * List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA.
   * Runs BEFORE signing so the catalog is covered by the run manifest, and
   * BEFORE the (future) W.W2 subprocessor screen that consumes it.
   */
  prohibitedVendorsCatalog: boolean;
  /**
   * When true (LOOP-W.W2), screen the subprocessor sheet + SBOM (transitively) +
   * OCI image publishers + inventory provider tags against the W.W1
   * prohibited-vendor catalog and emit out/prohibited-vendors-screen-result.json
   * (+ .xlsx). Runs AFTER the catalog (which it consumes) and BEFORE signing so
   * the screen result is covered by the run manifest. FAR 52.204-25 applies to
   * every federal acquisition since 2020-08-13 (no opt-out).
   */
  prohibitedVendorScreen: boolean;
  /**
   * When true (LOOP-W.W3), ingest the W.W2 screen result and emit a signed FAR
   * 52.204-25(d) 1-business-day discovery report (JSON + `.docx`) per reportable
   * (match × affected contract), with the federal-business-day deadline computed
   * per 5 U.S.C. §6103. Runs AFTER the W.W2 screen (which it consumes) and BEFORE
   * signing so the reports are covered by the run manifest. NEVER auto-transmits.
   */
  prohibitedVendor1bdReport: boolean;
  /**
   * When true (LOOP-W.W4), ingest the W.W2 screen result and emit the signed FAR
   * 52.204-26 Section 889 Part B annual representation (canonical-JSON envelope +
   * printable `.docx`) — the SAM.gov "does / does not" representation, driven by
   * the screen's non-suppressed matches, plus the LOOP-Q.Q1 Marketplace badge
   * feed. Runs AFTER the W.W2 screen + W.W3 reporter (it links W.W3 incidents) and
   * BEFORE signing so the artifacts are covered by the run manifest. NEVER files
   * the representation in SAM.gov on the operator's behalf (REO Rule 4).
   */
  section889AnnualRep: boolean;
  /**
   * When true (LOOP-T.T2), join the T.T1 SSDF practices catalogue to the run's
   * real evidence corpus (signed KSI envelopes + risk-scores + subprocessor /
   * supply-chain registers + SBOM + OSCAL POA&M) and emit the per-practice x
   * per-task SSDF satisfaction matrix (out/ssdf-satisfaction-matrix.json + .xlsx).
   * Runs AFTER every per-loop emitter and BEFORE signing so the matrix is
   * covered by the run manifest. Off by default (OMB M-22-18 procurement gate).
   */
  ssdfAttestation: boolean;
  /**
   * When true (LOOP-T.T3), project the T.T2 satisfaction matrix + the operator's
   * `ssdf.producer` config into the CISA Secure Software Development Attestation
   * Common Form (OMB 1670-0052) and emit the unsigned canonical PDF + signed JSON
   * shadow (out/cisa-common-form-1670-0052.{pdf,json}). Runs AFTER the T.T2 matrix
   * emit and BEFORE signing. Never auto-signs the human attestation (REO Rule 1.10).
   */
  ssdfCommonForm: boolean;
  /** Max SBOM transitive-dependency depth walked by the W.W2 screen (default 8). */
  sbomMaxDepth: number;
  /** Max subsidiary-chain depth walked by the W.W2 screen (default 3). */
  maxSubsidiaryDepth: number;
  /**
   * When true (LOOP-B.B1), compute per-finding composite risk scores
   * (CVSS+EPSS+criticality+exposure) and emit out/risk-scores.json. Runs
   * BEFORE the OSCAL POA&M emitter so the scores flow onto poam-item props,
   * and BEFORE signing so risk-scores.json is covered by the run manifest.
   */
  riskScore: boolean;
  /** Path to risk-config.yaml (weights, EPSS settings, CVSS overrides). */
  riskConfigPath: string | null;
  /** When true, disable the live EPSS feed for this run (overrides config). */
  riskNoEpss: boolean;
  /**
   * Path to an operator subprocessor config (YAML/JSON) for the SA-9
   * Subprocessor Inventory (LOOP-J.J2). When set (or when the config.yaml
   * `subprocessors` block is present), the orchestrator emits a signed
   * subprocessor-inventory.json + .xlsx BEFORE the OSCAL SSP (which consumes it
   * for leveraged-authorizations) and BEFORE signing.
   */
  subprocessorsConfig: string | null;
  /**
   * When true (LOOP-J.J3), emit the signed supply-chain risk register
   * (out/supply-chain-risk-register.json + .xlsx) joining SBOM CVEs + CISA KEV
   * exposure + subprocessor risk tiers + operator-asserted risks. Runs AFTER
   * the SBOM + subprocessor passes and BEFORE the OSCAL SSP/POA&M (which consume
   * it) and signing.
   */
  supplyChainRisk: boolean;
  /** Path to an operator --risks-config (YAML/JSON) for supply-chain risks. */
  risksConfig: string | null;
  /**
   * When true (LOOP-B.B2), fail the run (non-zero exit) if any POA&M finding's
   * remediation deadline fell through to `severity-fallback` — a sign the
   * FedRAMP CMP table was not loaded. CI sets this so a fallback can never reach
   * origin/main / a submission package.
   */
  strictRisk: boolean;
  /**
   * When true (LOOP-E.E1), emit the monthly ConMon analysis report
   * (out/conmon-monthly-<YYYY-MM>.{json,md,pdf}) aggregating posture + scan
   * coverage + POA&M activity + KEV exposure from the run's own artifacts.
   * Runs AFTER POA&M / VDR / inventory but BEFORE signing so the report is
   * covered by the run manifest.
   */
  conmonMonthly: boolean;
  /** Report month (YYYY-MM) for --conmon-monthly. Defaults to the current UTC month. */
  conmonMonth: string | null;
  /** FedRAMP-assigned package id (REQUIRES-OPERATOR-INPUT when absent). */
  fedrampPackageId: string | null;
  /** CSP legal corporate name for the monthly report header. */
  cspName: string | null;
  /** Href of the ConMon Strategy doc (C.C6) cited in the monthly report header. */
  conmonStrategyHref: string | null;
  /** Internal-only scan sampling percentage (0..100; default 100 — the FedRAMP MUST). */
  samplingPct: number | null;
  /** ISO date the SSP was last reviewed (annual cycle; from E.E4 when it ships). */
  sspLastReviewed: string | null;
  /** Authorization date (YYYY-MM-DD) anchoring the monthly report's annual-cycle math. */
  authorizationDate: string | null;
  /** LOOP-B.B3: tracker base URL to pull signed risk acceptances from before the POA&M emit. */
  trackerUrl: string | null;
  /** LOOP-B.B3: Bearer token for the tracker risk-acceptance API. */
  trackerApiToken: string | null;
  /** LOOP-B.B4: tracker base URL to pull signed compensating controls from before the POA&M emit (defaults to trackerUrl). */
  compensatingControlsUrl: string | null;
  /**
   * When true (LOOP-B.B5), aggregate the OSCAL POA&M risks (B.B1+B.B2) + signed
   * acceptances (B.B3) + compensating controls (B.B4) + operator-entered
   * organisational risks into out/risk-register.json + out/risk-register.xlsx
   * (the NIST RA-3 deliverable). Runs AFTER the POA&M emit (which it reads) and
   * BEFORE signing so both artifacts are covered by the run manifest.
   */
  riskRegister: boolean;
  /** LOOP-B.B5: tracker base URL to pull organisational risks from before the register emit (defaults to trackerUrl). */
  organisationalRisksUrl: string | null;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    providers: ['aws', 'gcp', 'azure'],
    ksiFilter: null,
    impactLevel: (process.env.CLOUD_EVIDENCE_IMPACT_LEVEL as ImpactTier) || null,
    framework: (process.env.CLOUD_EVIDENCE_FRAMEWORK as BenchmarkFramework) === 'rev5' ? 'rev5' : '20x',
    outDir: resolve(PROJECT_ROOT, 'out'),
    configPath: resolve(PROJECT_ROOT, 'config.yaml'),
    dryRun: false,
    htmlReport: false,
    csvExport: false,
    diffReport: false,
    scn: process.env.CLOUD_EVIDENCE_SCN === '1',
    scnProposedPath: process.env.CLOUD_EVIDENCE_SCN_PROPOSED_PATH ?? null,
    pushParamify: false,
    pushTracker: false,
    notifyOnDrift: false,
    strictSchema: false,
    concurrency: Number(process.env.CLOUD_EVIDENCE_CONCURRENCY ?? 4),
    noSign: process.env.CLOUD_EVIDENCE_NO_SIGN === '1',
    expectedPublicKey: process.env.EVIDENCE_EXPECTED_PUBLIC_KEY_PATH ?? null,
    oscal: process.env.CLOUD_EVIDENCE_OSCAL === '1',
    oscalSsp: process.env.CLOUD_EVIDENCE_OSCAL_SSP === '1',
    oscalPoam: process.env.CLOUD_EVIDENCE_OSCAL_POAM === '1',
    oscalAp: process.env.CLOUD_EVIDENCE_OSCAL_AP === '1',
    strictChain: process.env.CLOUD_EVIDENCE_STRICT_CHAIN === '1',
    submissionBundle: process.env.CLOUD_EVIDENCE_SUBMISSION_BUNDLE === '1',
    strictBundle: process.env.CLOUD_EVIDENCE_STRICT_BUNDLE === '1',
    roe: process.env.CLOUD_EVIDENCE_ROE === '1',
    cmp: process.env.CLOUD_EVIDENCE_CMP === '1',
    cmpApprovalNarrative: process.env.CLOUD_EVIDENCE_CMP_APPROVAL_NARRATIVE ?? null,
    cmpRollbackAuthority: process.env.CLOUD_EVIDENCE_CMP_ROLLBACK_AUTHORITY ?? null,
    cmpChangeWindows: process.env.CLOUD_EVIDENCE_CMP_CHANGE_WINDOWS ?? null,
    cmpBaselineConfigHref: process.env.CLOUD_EVIDENCE_CMP_BASELINE_CONFIG_HREF ?? null,
    iscp: process.env.CLOUD_EVIDENCE_ISCP === '1',
    iscpTestAar: process.env.CLOUD_EVIDENCE_ISCP_TEST_AAR === '1',
    iscpRtoHours: process.env.CLOUD_EVIDENCE_ISCP_RTO_HOURS ? Number(process.env.CLOUD_EVIDENCE_ISCP_RTO_HOURS) : null,
    iscpRpoHours: process.env.CLOUD_EVIDENCE_ISCP_RPO_HOURS ? Number(process.env.CLOUD_EVIDENCE_ISCP_RPO_HOURS) : null,
    iscpTestDate: process.env.CLOUD_EVIDENCE_ISCP_TEST_DATE ?? null,
    iscpTestType: process.env.CLOUD_EVIDENCE_ISCP_TEST_TYPE ?? null,
    irp: process.env.CLOUD_EVIDENCE_IRP === '1',
    irpTestAar: process.env.CLOUD_EVIDENCE_IRP_TEST_AAR === '1',
    irpSpecVersion: process.env.CLOUD_EVIDENCE_IRP_SPEC_VERSION ?? null,
    apRoeHref: process.env.CLOUD_EVIDENCE_AP_ROE_HREF ?? null,
    apSamplingMethodologyHref: process.env.CLOUD_EVIDENCE_AP_SAMPLING_HREF ?? null,
    thirdPartyAssessor: process.env.CLOUD_EVIDENCE_3PAO_NAME ?? null,
    sspDocx: process.env.CLOUD_EVIDENCE_SSP_DOCX === '1',
    oscalOrgName: process.env.CLOUD_EVIDENCE_ORG_NAME ?? null,
    systemName: process.env.CLOUD_EVIDENCE_SYSTEM_NAME ?? null,
    systemId: process.env.CLOUD_EVIDENCE_SYSTEM_ID ?? null,
    crosswalk: process.env.CLOUD_EVIDENCE_CROSSWALK === '1',
    inventoryWorkbook: process.env.CLOUD_EVIDENCE_INVENTORY_WORKBOOK === '1',
    inventoryOnly: false,
    referenceArch: process.env.CLOUD_EVIDENCE_REFERENCE_ARCH === '1',
    awsOrgFanout: process.env.CLOUD_EVIDENCE_AWS_ORG_FANOUT === '1',
    awsFanoutInclude: (process.env.CLOUD_EVIDENCE_AWS_INCLUDE ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    awsFanoutExclude: (process.env.CLOUD_EVIDENCE_AWS_EXCLUDE ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    awsCrossAccountRole: process.env.AWS_CROSS_ACCOUNT_ROLE ?? null,
    powerpipe: process.env.CLOUD_EVIDENCE_POWERPIPE === '1',
    sbomDir: process.env.CLOUD_EVIDENCE_SBOM_DIR ?? null,
    anomaly: process.env.CLOUD_EVIDENCE_ANOMALY === '1',
    pluginsDir: process.env.CLOUD_EVIDENCE_PLUGINS_DIR ?? null,
    llmGeneratePrs: process.env.CLOUD_EVIDENCE_LLM_PRS === '1',
    ticketProvider: (process.env.CLOUD_EVIDENCE_TICKET_PROVIDER as Args['ticketProvider']) ?? null,
    siemUrl: process.env.CLOUD_EVIDENCE_SIEM_URL ?? null,
    webhookUrl: process.env.CLOUD_EVIDENCE_WEBHOOK_URL ?? null,
    prohibitedVendorsCatalog: process.env.CLOUD_EVIDENCE_PROHIBITED_VENDORS_CATALOG === '1',
    prohibitedVendorScreen: process.env.CLOUD_EVIDENCE_PROHIBITED_VENDOR_SCREEN === '1',
    prohibitedVendor1bdReport: process.env.CLOUD_EVIDENCE_PROHIBITED_VENDOR_1BD_REPORT === '1',
    section889AnnualRep: process.env.CLOUD_EVIDENCE_SECTION889_ANNUAL_REP === '1',
    ssdfAttestation: process.env.CLOUD_EVIDENCE_SSDF_ATTESTATION === '1' || process.env.CLOUD_EVIDENCE_SSDF_ATTESTATION === 'true',
    ssdfCommonForm: process.env.CLOUD_EVIDENCE_SSDF_COMMON_FORM === '1' || process.env.CLOUD_EVIDENCE_SSDF_COMMON_FORM === 'true',
    sbomMaxDepth: Number(process.env.CLOUD_EVIDENCE_SBOM_MAX_DEPTH ?? 8),
    maxSubsidiaryDepth: Number(process.env.CLOUD_EVIDENCE_MAX_SUBSIDIARY_DEPTH ?? 3),
    riskScore: process.env.CLOUD_EVIDENCE_RISK_SCORE === '1',
    riskConfigPath: process.env.CLOUD_EVIDENCE_RISK_CONFIG ?? null,
    riskNoEpss: process.env.CLOUD_EVIDENCE_RISK_NO_EPSS === '1',
    subprocessorsConfig: process.env.CLOUD_EVIDENCE_SUBPROCESSORS_CONFIG ?? null,
    supplyChainRisk: process.env.CLOUD_EVIDENCE_SUPPLY_CHAIN_RISK === '1',
    risksConfig: process.env.CLOUD_EVIDENCE_RISKS_CONFIG ?? null,
    strictRisk: process.env.CLOUD_EVIDENCE_STRICT_RISK === '1',
    conmonMonthly: process.env.CLOUD_EVIDENCE_CONMON_MONTHLY === '1',
    conmonMonth: process.env.CLOUD_EVIDENCE_CONMON_MONTH ?? null,
    fedrampPackageId: process.env.CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID ?? null,
    cspName: process.env.CLOUD_EVIDENCE_CSP_NAME ?? null,
    conmonStrategyHref: process.env.CLOUD_EVIDENCE_CONMON_STRATEGY_HREF ?? null,
    samplingPct: process.env.CLOUD_EVIDENCE_SAMPLING_PCT ? Number(process.env.CLOUD_EVIDENCE_SAMPLING_PCT) : null,
    sspLastReviewed: process.env.CLOUD_EVIDENCE_SSP_LAST_REVIEWED ?? null,
    authorizationDate: process.env.CLOUD_EVIDENCE_AUTHORIZATION_DATE ?? null,
    trackerUrl: process.env.CLOUD_EVIDENCE_TRACKER_URL ?? null,
    trackerApiToken: process.env.CLOUD_EVIDENCE_TRACKER_TOKEN ?? null,
    compensatingControlsUrl: process.env.CLOUD_EVIDENCE_COMPENSATING_CONTROLS_URL ?? null,
    riskRegister: process.env.CLOUD_EVIDENCE_RISK_REGISTER === '1',
    organisationalRisksUrl: process.env.CLOUD_EVIDENCE_ORGANISATIONAL_RISKS_URL ?? null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--providers':
        args.providers = (argv[++i] ?? '').split(',').filter(Boolean) as Args['providers'];
        break;
      case '--ksis':
        args.ksiFilter = (argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--impact-level': {
        const v = (argv[++i] ?? '').toLowerCase();
        if (!['low', 'moderate', 'high'].includes(v)) {
          console.error(`--impact-level must be one of: low, moderate, high (got: ${v})`);
          process.exit(2);
        }
        args.impactLevel = v as ImpactTier;
        break;
      }
      case '--framework': {
        const v = (argv[++i] ?? '').toLowerCase();
        if (!['rev5', '20x'].includes(v)) {
          console.error(`--framework must be one of: rev5, 20x (got: ${v})`);
          process.exit(2);
        }
        args.framework = v as BenchmarkFramework;
        break;
      }
      case '--out':
        args.outDir = resolve(argv[++i] ?? './out');
        break;
      case '--config':
        args.configPath = resolve(argv[++i] ?? './config.yaml');
        break;
      case '--dry-run':
        args.dryRun = true;
        break;
      case '--html-report':
        args.htmlReport = true;
        break;
      case '--csv-export':
        args.csvExport = true;
        break;
      case '--diff-report':
        args.diffReport = true;
        break;
      case '--scn':
        args.scn = true;
        args.diffReport = true;   // SCN consumes diff-report.json — make sure it gets written
        break;
      case '--scn-proposed':
        args.scnProposedPath = resolve(argv[++i] ?? '');
        break;
      case '--push-paramify':
        args.pushParamify = true;
        break;
      case '--push-tracker':
        args.pushTracker = true;
        break;
      case '--notify-on-drift':
        args.notifyOnDrift = true;
        break;
      case '--strict-schema':
        args.strictSchema = true;
        break;
      case '--concurrency': {
        const n = Number(argv[++i] ?? '4');
        if (Number.isFinite(n) && n >= 1) args.concurrency = Math.floor(n);
        break;
      }
      case '--no-sign':
        args.noSign = true;
        break;
      case '--expected-public-key':
        args.expectedPublicKey = resolve(argv[++i] ?? '');
        break;
      case '--oscal':
        args.oscal = true;
        break;
      case '--oscal-ssp':
        args.oscalSsp = true;
        break;
      case '--oscal-poam':
        // LOOP-A.A1: emit OSCAL POA&M v1.1.2 + XML.
        args.oscalPoam = true;
        break;
      case '--oscal-ap':
        // LOOP-A.A2: emit OSCAL Assessment Plan v1.1.2 + XML.
        args.oscalAp = true;
        break;
      case '--strict-chain':
        // LOOP-A.A3: refuse to emit an AR with a synthetic import-ap.
        args.strictChain = true;
        break;
      case '--submission-bundle':
        // LOOP-A.A4: build the signed FedRAMP 20x submission tarball.
        args.submissionBundle = true;
        break;
      case '--strict-bundle':
        // LOOP-A.A4: refuse to write a bundle with gaps or a broken chain.
        args.strictBundle = true;
        args.submissionBundle = true;
        break;
      case '--roe':
        // LOOP-A.A5: emit Rules of Engagement Word template seed.
        args.roe = true;
        break;
      case '--cmp':
        // LOOP-C.C1: emit the Configuration Management Plan (CM-9) Word doc.
        args.cmp = true;
        break;
      case '--cmp-approval-narrative':
        args.cmpApprovalNarrative = argv[++i] ?? null;
        break;
      case '--cmp-rollback-authority':
        args.cmpRollbackAuthority = argv[++i] ?? null;
        break;
      case '--cmp-change-windows':
        args.cmpChangeWindows = argv[++i] ?? null;
        break;
      case '--cmp-baseline-config-href':
        args.cmpBaselineConfigHref = argv[++i] ?? null;
        break;
      case '--iscp':
        // LOOP-C.C2: emit the Information System Contingency Plan (CP-2) Word doc.
        args.iscp = true;
        break;
      case '--iscp-test-aar':
        // LOOP-C.C2: emit the Contingency Plan Test After-Action Report (CP-4).
        args.iscpTestAar = true;
        break;
      case '--iscp-rto-hours':
        args.iscpRtoHours = argv[++i] != null ? Number(argv[i]) : null;
        break;
      case '--iscp-rpo-hours':
        args.iscpRpoHours = argv[++i] != null ? Number(argv[i]) : null;
        break;
      case '--iscp-test-date':
        args.iscpTestDate = argv[++i] ?? null;
        break;
      case '--iscp-test-type':
        args.iscpTestType = argv[++i] ?? null;
        break;
      case '--irp':
        args.irp = true;
        break;
      case '--irp-test-aar':
        args.irpTestAar = true;
        break;
      case '--irp-spec-version':
        args.irpSpecVersion = argv[++i] ?? null;
        break;
      case '--prohibited-vendors-catalog':
        // LOOP-W.W1: emit the signed prohibited-vendor catalog.
        args.prohibitedVendorsCatalog = true;
        break;
      case '--prohibited-vendor-screen':
        // LOOP-W.W2: screen the four surfaces against the W.W1 catalog.
        args.prohibitedVendorScreen = true;
        break;
      case '--prohibited-vendor-1bd-report':
        // LOOP-W.W3: emit FAR 52.204-25(d) 1-business-day reports from W.W2 hits.
        args.prohibitedVendor1bdReport = true;
        break;
      case '--section889-annual-rep':
        // LOOP-W.W4: emit the FAR 52.204-26 annual representation (JSON + .docx).
        args.section889AnnualRep = true;
        break;
      case '--ssdf-attestation':
        // LOOP-T.T2: emit the SSDF per-practice satisfaction matrix (JSON + .xlsx).
        args.ssdfAttestation = true;
        break;
      case '--ssdf-common-form':
        // LOOP-T.T3: emit the CISA Common Form (OMB 1670-0052) PDF + JSON.
        // Implies --ssdf-attestation (the matrix is the form's evidence backbone).
        args.ssdfCommonForm = true;
        args.ssdfAttestation = true;
        break;
      case '--sbom-max-depth':
        args.sbomMaxDepth = Number(argv[++i] ?? 8);
        break;
      case '--max-subsidiary-depth':
        args.maxSubsidiaryDepth = Number(argv[++i] ?? 3);
        break;
      case '--risk-score':
        // LOOP-B.B1: compute per-finding composite risk scores.
        args.riskScore = true;
        break;
      case '--risk-config':
        args.riskConfigPath = argv[++i] ?? null;
        break;
      case '--risk-no-epss':
        // Disable the live EPSS feed for this run (offline / air-gapped).
        args.riskNoEpss = true;
        break;
      case '--subprocessors-config':
        // LOOP-J.J2: operator subprocessor config (YAML/JSON) for the SA-9 inventory.
        args.subprocessorsConfig = argv[++i] ?? null;
        break;
      case '--supply-chain-risk':
        // LOOP-J.J3: emit the signed SR-3 supply-chain risk register.
        args.supplyChainRisk = true;
        break;
      case '--risks-config':
        // LOOP-J.J3: operator-asserted supply-chain risks + mitigation overrides.
        args.risksConfig = argv[++i] ?? null;
        break;
      case '--strict-risk':
        // LOOP-B.B2: fail the run if any deadline falls through to severity-fallback.
        args.strictRisk = true;
        break;
      case '--conmon-monthly':
        // LOOP-E.E1: emit the monthly ConMon analysis report (json/md/pdf).
        args.conmonMonthly = true;
        break;
      case '--month':
        args.conmonMonth = argv[++i] ?? null;
        break;
      case '--fedramp-package-id':
        args.fedrampPackageId = argv[++i] ?? null;
        break;
      case '--csp-name':
        args.cspName = argv[++i] ?? null;
        break;
      case '--conmon-strategy-href':
        args.conmonStrategyHref = argv[++i] ?? null;
        break;
      case '--sampling-pct': {
        const n = Number(argv[++i] ?? '');
        if (Number.isFinite(n) && n >= 0 && n <= 100) args.samplingPct = n;
        else {
          console.error('--sampling-pct must be a number in [0, 100]');
          process.exit(2);
        }
        break;
      }
      case '--ssp-last-reviewed':
        args.sspLastReviewed = argv[++i] ?? null;
        break;
      case '--authorization-date':
        args.authorizationDate = argv[++i] ?? null;
        break;
      case '--pull-risk-acceptances':
        // LOOP-B.B3: pull signed risk acceptances from the tracker before the POA&M emit.
        args.trackerUrl = argv[++i] ?? null;
        break;
      case '--tracker-api-token':
        args.trackerApiToken = argv[++i] ?? null;
        break;
      case '--pull-compensating-controls':
        // LOOP-B.B4: pull signed compensating controls from the tracker before the
        // POA&M emit. Defaults to the same tracker URL as --pull-risk-acceptances.
        args.compensatingControlsUrl = argv[++i] ?? null;
        break;
      case '--risk-register':
        // LOOP-B.B5: aggregate the Central Risk Register (RA-3) after the POA&M emit.
        args.riskRegister = true;
        break;
      case '--pull-organisational-risks':
        // LOOP-B.B5: pull operator-entered organisational risks from the tracker
        // before the register emit. Defaults to the --pull-risk-acceptances URL.
        args.organisationalRisksUrl = argv[++i] ?? null;
        break;
      case '--ap-roe-href':
        args.apRoeHref = argv[++i] ?? null;
        break;
      case '--ap-sampling-href':
        args.apSamplingMethodologyHref = argv[++i] ?? null;
        break;
      case '--3pao-name':
        args.thirdPartyAssessor = argv[++i] ?? null;
        break;
      case '--ssp-docx':
        args.sspDocx = true;
        args.oscalSsp = true;   // need the SSP JSON to render the Word doc
        break;
      case '--oscal-org':
        args.oscalOrgName = argv[++i] ?? null;
        break;
      case '--system-name':
        args.systemName = argv[++i] ?? null;
        break;
      case '--system-id':
        args.systemId = argv[++i] ?? null;
        break;
      case '--crosswalk':
        args.crosswalk = true;
        break;
      case '--inventory-workbook':
        args.inventoryWorkbook = true;
        break;
      case '--inventory-only':
        args.inventoryOnly = true;
        args.inventoryWorkbook = true;
        args.ksiFilter = [];   // no KSI collectors run
        break;
      case '--reference-arch':
        args.referenceArch = true;
        break;
      case '--aws-org-fanout':
        args.awsOrgFanout = true;
        break;
      case '--aws-include':
        args.awsFanoutInclude = (argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--aws-exclude':
        args.awsFanoutExclude = (argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--aws-cross-account-role':
        args.awsCrossAccountRole = argv[++i] ?? null;
        break;
      case '--powerpipe':
        args.powerpipe = true;
        break;
      case '--sbom-dir':
        args.sbomDir = resolve(argv[++i] ?? '');
        break;
      case '--anomaly':
        args.anomaly = true;
        break;
      case '--plugins-dir':
        args.pluginsDir = resolve(argv[++i] ?? '');
        break;
      case '--llm-generate-prs':
        args.llmGeneratePrs = true;
        break;
      case '--ticket-push': {
        const v = argv[++i] ?? '';
        if (!['github', 'jira', 'servicenow'].includes(v)) {
          console.error(`--ticket-push must be one of: github, jira, servicenow (got: ${v})`);
          process.exit(2);
        }
        args.ticketProvider = v as Args['ticketProvider'];
        break;
      }
      case '--siem-url':
        args.siemUrl = argv[++i] ?? null;
        break;
      case '--webhook-url':
        args.webhookUrl = argv[++i] ?? null;
        break;
      case '--all-reports':
        args.htmlReport = true;
        args.csvExport = true;
        args.diffReport = true;
        break;
      case '--help': case '-h':
        printHelp();
        process.exit(0);
    }
  }
  // Rendering the SSP Word doc requires the SSP JSON (covers env-set CLOUD_EVIDENCE_SSP_DOCX).
  if (args.sspDocx) args.oscalSsp = true;
  // SCN consumes diff-report.json — guarantee it's produced (covers env-set CLOUD_EVIDENCE_SCN).
  if (args.scn) args.diffReport = true;
  return args;
}

function printHelp(): void {
  console.log(`cloud-evidence orchestrator

Read-only collector for FedRAMP 20x KSI evidence on AWS and GCP.

Usage:
  tsx core/orchestrator.ts [options]

Options:
  --providers <list>     Comma-separated providers (default: aws,gcp,azure; azure is silently
                         skipped unless config.azure.enabled is true)
  --ksis <list>          Comma-separated KSI IDs (default: all supported)
  --out <dir>            Output directory (default: ./out)
  --config <file>        Config file path (default: ./config.yaml)
  --dry-run              Plan only; do not call any SDK

Post-run artifacts:
  --html-report          Generate self-contained HTML report (out/report.html)
  --csv-export           Export all findings as CSV (out/findings.csv)
  --diff-report          Generate run-over-run diff (out/diff-report.{json,html})
  --scn                  Classify the run's diff as a FedRAMP Significant Change Notification
                         report (out/scn-classification.json + scn-notice-draft.md). Implies
                         --diff-report. (env: CLOUD_EVIDENCE_SCN)
  --scn-proposed <path>  Optional JSON file of operator-proposed changes to include in the SCN
                         classification (env: CLOUD_EVIDENCE_SCN_PROPOSED_PATH)
  --all-reports          Shortcut for the three above
  --notify-on-drift      Send Slack/PagerDuty notification on negative drift
  --strict-schema        Fail-hard if any emitted EvidenceFile violates the schema
  --concurrency <N>      Max concurrent KSI collections (default 4, env: CLOUD_EVIDENCE_CONCURRENCY)
  --no-sign              Skip Ed25519 signing of the run manifest (env: CLOUD_EVIDENCE_NO_SIGN=1)
  --expected-public-key  PEM path; assert manifest's embedded key matches (defense vs. key substitution)
  --oscal                Emit OSCAL 1.1 Assessment Results (out/assessment-results.json)
  --oscal-ssp            Emit a DRAFT OSCAL 1.1 System Security Plan (out/ssp.json) bootstrapped
                         from evidence: one implemented-requirement per FedRAMP baseline control,
                         status derived from the control benchmark (env: CLOUD_EVIDENCE_OSCAL_SSP)
  --ssp-docx             Also render the SSP to a FedRAMP-style Word document (out/ssp.docx).
                         Implies --oscal-ssp (env: CLOUD_EVIDENCE_SSP_DOCX)
  --oscal-poam           Emit an OSCAL 1.1.2 Plan of Action and Milestones (out/poam.json + .xml)
                         from failing findings. One poam-item per failing finding, with deterministic
                         deadlines per FedRAMP ConMon table (Critical 30d, High 60d, Med 90d, Low 180d).
                         Skipped automatically when there are zero failing findings (OSCAL schema
                         mandates poam-items.minItems=1; a "clean POA&M" is reported as a structured
                         skip-result, not a missing-evidence error). (env: CLOUD_EVIDENCE_OSCAL_POAM)
  --conmon-monthly       LOOP-E.E1: emit the monthly ConMon analysis report
                         (out/conmon-monthly-<YYYY-MM>.{json,md,pdf}) — posture + scan coverage
                         + POA&M activity + KEV exposure aggregated from the run's own artifacts.
                         Runs before signing so the report is in the manifest. (env: CLOUD_EVIDENCE_CONMON_MONTHLY)
  --month <YYYY-MM>      Report month for --conmon-monthly (default: current UTC month).
                         (env: CLOUD_EVIDENCE_CONMON_MONTH)
  --fedramp-package-id <id>  FedRAMP-assigned package id for the monthly report
                         (REQUIRES-OPERATOR-INPUT when absent). (env: CLOUD_EVIDENCE_FEDRAMP_PACKAGE_ID)
  --csp-name <name>      CSP legal corporate name for the monthly report. (env: CLOUD_EVIDENCE_CSP_NAME)
  --conmon-strategy-href <h>  Href of the ConMon Strategy doc (C.C6) cited in the report header.
                         (env: CLOUD_EVIDENCE_CONMON_STRATEGY_HREF)
  --sampling-pct <0-100> Internal-only scan sampling percentage (default 100 — the FedRAMP MUST).
                         (env: CLOUD_EVIDENCE_SAMPLING_PCT)
  --ssp-last-reviewed <ISO>  Date the SSP was last reviewed (annual cycle). (env: CLOUD_EVIDENCE_SSP_LAST_REVIEWED)
  --authorization-date <YYYY-MM-DD>  Authorization date anchoring the report's annual-cycle math.
                         (env: CLOUD_EVIDENCE_AUTHORIZATION_DATE)
  --oscal-ap             Emit an OSCAL 1.1.2 Assessment Plan / SAP draft (out/ap.json + .xml).
                         Import-SSP href defaults to "ssp.json" (override with --ap-ssp-href via env).
                         reviewed-controls enumerates the full FedRAMP baseline at the impact tier;
                         local-definitions.activities[] registers one activity per KSI in the ksi-map;
                         assessment-subjects derive from out/inventory.json when present.
                         The 3PAO refines this draft + signs the finalized AP before testing.
                         (env: CLOUD_EVIDENCE_OSCAL_AP)
  --ap-roe-href <href>   Rules of Engagement document href (back-matter resource link)
                         (env: CLOUD_EVIDENCE_AP_ROE_HREF)
  --ap-sampling-href <h> Sampling Methodology (Appendix B) href (back-matter resource link)
                         (env: CLOUD_EVIDENCE_AP_SAMPLING_HREF)
  --3pao-name <name>     3PAO organization name to record on the AP (env: CLOUD_EVIDENCE_3PAO_NAME)
  --strict-chain         Fail emission of the OSCAL AR if its mandatory import-ap href cannot
                         be resolved to a real document (no AP co-emitted AND no explicit
                         --ap-href). Prevents shipping a submission package with a synthetic
                         AP anchor. (env: CLOUD_EVIDENCE_STRICT_CHAIN)
  --submission-bundle    Build a signed FedRAMP 20x submission package
                         (out/submission-package.tar.gz). Bundles SSP+AP+AR+POA&M+IIW
                         + per-KSI evidence + signed manifest + RFC 3161 timestamp +
                         INDEX.json with chain integrity check + sha256 per artifact.
                         The bundle is what a CSP uploads to the FedRAMP secure repository.
                         (env: CLOUD_EVIDENCE_SUBMISSION_BUNDLE)
  --strict-bundle        Implies --submission-bundle. Refuse to write the tarball if any
                         required artifact is missing OR the SSP→AP→AR→POA&M chain is
                         broken. The right setting for production submissions.
                         (env: CLOUD_EVIDENCE_STRICT_BUNDLE)
  --roe                  Emit a Rules of Engagement Word template (out/roe.docx)
                         pre-filled with system identity (--system-name / --system-id),
                         authorization-boundary narrative, IP ranges auto-derived from
                         inventory.json, scan windows (env-supplied), escalation contacts,
                         and the controls-in-scope KSI list. The 3PAO completes remaining
                         REQUIRES-OPERATOR-INPUT fields and obtains CSP + 3PAO signatures.
                         The RoE is referenced from the AP back-matter (LOOP-A.A2) and
                         included in the submission bundle (LOOP-A.A4).
                         (env: CLOUD_EVIDENCE_ROE)
  --cmp                  Emit the Configuration Management Plan (CM-9) Word document
                         (out/cmp.docx) — an 11-section plan whose Configuration Items
                         table is auto-derived from real inventory.json (CM-8) and whose
                         Configuration Monitoring list is derived from core/ksi-map.ts.
                         Process narratives fall back to REQUIRES-OPERATOR-INPUT (LOOP-C.C1).
                         (env: CLOUD_EVIDENCE_CMP)
  --cmp-approval-narrative <text>   §6 change-control workflow narrative
                         (env: CLOUD_EVIDENCE_CMP_APPROVAL_NARRATIVE; or config.yaml: cmp.approval_narrative)
  --cmp-rollback-authority <text>   §9 rollback authority + criteria
                         (env: CLOUD_EVIDENCE_CMP_ROLLBACK_AUTHORITY; or config.yaml: cmp.rollback_authority)
  --cmp-change-windows <text>       §8 approved change/maintenance windows
                         (env: CLOUD_EVIDENCE_CMP_CHANGE_WINDOWS; or config.yaml: cmp.change_windows)
  --cmp-baseline-config-href <ref>  §5 link to the CM-2 Baseline Configuration doc
                         (env: CLOUD_EVIDENCE_CMP_BASELINE_CONFIG_HREF; or config.yaml: cmp.baseline_config_href)
  --iscp                 Emit the Information System Contingency Plan (CP-2 / CP-9 / CP-10)
                         Word document (out/iscp.docx). §4.2 Recovery evidence is auto-filled
                         from the real signed RPL-family KSI files (KSI-RPL-ABO/TRC/RRO/ARP);
                         Appendix B from the real subprocessor inventory; recovery narratives
                         fall back to REQUIRES-OPERATOR-INPUT. Structured input comes from
                         config.yaml: iscp.* (LOOP-C.C2). (env: CLOUD_EVIDENCE_ISCP)
  --iscp-test-aar        Emit the Contingency Plan Test After-Action Report (CP-4) Word
                         document (out/iscp-test-aar.docx). Test scenarios + lessons learned
                         are operator-supplied via config.yaml: iscp.test.*; anchors to the
                         ISCP under test when --iscp ran in the same run (LOOP-C.C2).
                         (env: CLOUD_EVIDENCE_ISCP_TEST_AAR)
  --iscp-rto-hours <n>   §4.1 Recovery Time Objective in hours (overrides config.yaml: iscp.rto.hours)
  --iscp-rpo-hours <n>   §4.1 Recovery Point Objective in hours (overrides config.yaml: iscp.rpo.hours)
  --iscp-test-date <iso> AAR test date, ISO (overrides config.yaml: iscp.test.test_date)
  --iscp-test-type <t>   AAR test type: tabletop | functional | full-interruption
                         (overrides config.yaml: iscp.test.test_type)
  --irp                  Emit the Incident Response Plan (IR-8 / IR-3 / IR-4 / IR-6)
                         Word document (out/irp.docx), structured per NIST SP 800-61 Rev. 3
                         (CSF 2.0 phases). §4 Detect is auto-filled from the real KSI-INR-RIR
                         evidence; §9 Reporting SLAs come from the FedRAMP Incident
                         Communications Procedures; the IR-team roster + communications plan
                         fall back to REQUIRES-OPERATOR-INPUT. Structured input comes from
                         config.yaml: irp.* (LOOP-C.C3). (env: CLOUD_EVIDENCE_IRP)
  --irp-test-aar         Emit the Incident Response Test After-Action Report (IR-3) Word
                         document (out/irp-test-aar.docx). Test scenarios + the 5-phase timing
                         matrix + lessons learned are operator-supplied via config.yaml: irp.test.*;
                         anchors to the IRP under test when --irp ran the same run (LOOP-C.C3).
                         (env: CLOUD_EVIDENCE_IRP_TEST_AAR)
  --irp-spec-version <v> IR spec version: 800-61r2 | 800-61r3 (default 800-61r3, the current
                         NIST standard; overrides config.yaml: irp.spec_version)
  --system-name <name>   System name for the OSCAL SSP (env: CLOUD_EVIDENCE_SYSTEM_NAME)
  --system-id <id>       System identifier for the OSCAL SSP (env: CLOUD_EVIDENCE_SYSTEM_ID)
  --oscal-org <name>     Organization name to embed in OSCAL metadata (env: CLOUD_EVIDENCE_ORG_NAME)
  --crosswalk            Emit crosswalk-report.json (NIST → SOC2/ISO27001/HIPAA mapping)
  --inventory-workbook   Enumerate cloud assets and emit the FedRAMP Integrated Inventory
                         Workbook (out/inventory-workbook.{csv,xlsx}) + inventory.json,
                         OSCAL inventory-items, CMDB records, and a run-over-run diff
                         for AWS + GCP (env: CLOUD_EVIDENCE_INVENTORY_WORKBOOK)
  --inventory-only       Fast inventory-focused run: only the inventory (skip KSI
                         collection + process evidence). Implies --inventory-workbook.
  --reference-arch       Audit the running env against FedRAMP reference-architecture
                         hardening (Coalfire RAMPpak-derived) and emit
                         AUDIT-REFARCH-{AWS,GCP}.json evidence that flows into the
                         benchmark/OSCAL/crosswalk (env: CLOUD_EVIDENCE_REFERENCE_ARCH).
                         AMI/API allow-patterns: CLOUD_EVIDENCE_APPROVED_AMI_PATTERN,
                         CLOUD_EVIDENCE_GCP_API_ALLOWLIST.
  --framework <fw>       NIST 800-53 control-benchmark framing: rev5 (full 800-53B baseline) or 20x
                         (only controls the 20x KSIs reference). Default 20x. Emits control-benchmark.json
                         (env: CLOUD_EVIDENCE_FRAMEWORK)

Multi-account (AWS Organizations):
  --aws-org-fanout       Discover member accounts and collect across all of them
  --aws-include <list>   Only collect these account IDs (comma-separated)
  --aws-exclude <list>   Skip these account IDs (comma-separated)
  --aws-cross-account-role <name>  Role to assume in member accounts (default: OrganizationAccountAccessRole)

Powerpipe / Steampipe:
  --powerpipe            Emit a Powerpipe mod under out/powerpipe/ (one control per KSI)
  --sbom-dir <path>      Parse SBOM files in this dir (CycloneDX/SPDX) and emit sbom-report.json
  --anomaly              Compare this run to the rolling baseline; emit anomaly-report.json
  --plugins-dir <path>   Load custom KSI collectors from this directory (env: CLOUD_EVIDENCE_PLUGINS_DIR)

Phase F integrations (opt-in; require env vars):
  --llm-generate-prs     Generate remediation PRs via Anthropic Claude for each failing finding (env: ANTHROPIC_API_KEY)
  --ticket-push <prov>   Push failing findings to github | jira | servicenow (env: respective driver vars; see RUNBOOK)
  --siem-url <url>       Push OCSF compliance_finding events to a SIEM intake URL (env: CLOUD_EVIDENCE_SIEM_AUTH)
  --webhook-url <url>    Send HMAC-signed webhook to URL (env: CLOUD_EVIDENCE_WEBHOOK_SECRET)

Integrations (opt-in; require env vars):
  --push-paramify        Push to Paramify (PARAMIFY_API_TOKEN)
  --push-tracker         Push to local tracker (TRACKER_API_TOKEN, TRACKER_BASE_URL)

  -h, --help             Show this help

Supported KSIs (Phase 1):
  ${SUPPORTED_KSIS.join('\n  ')}
`);
}

/**
 * Translate a filesystem error into an operator-actionable message. The raw
 * Node errors (ENOSPC, EACCES, EROFS, …) are cryptic; a runner staring at a
 * crashed collection wants to know "disk full" or "fix the directory perms".
 */
function describeFsError(e: any, path: string, op: string): string {
  const code = e?.code;
  switch (code) {
    case 'ENOSPC': return `Disk full while ${op} ${path}. Free space or point --out at a larger volume.`;
    case 'EACCES':
    case 'EPERM':  return `Permission denied ${op} ${path}. Check directory ownership/permissions for the runner user.`;
    case 'EROFS':  return `Read-only filesystem ${op} ${path}. Point --out at a writable location.`;
    case 'ENOENT': return `Parent directory missing ${op} ${path}. The output directory could not be created.`;
    case 'EMFILE':
    case 'ENFILE': return `Too many open files ${op} ${path}. Raise the ulimit (ulimit -n) and retry.`;
    case 'EISDIR': return `Expected a file but found a directory at ${path} (${op}).`;
    default:       return `Failed ${op} ${path}: ${e?.message ?? String(e)}${code ? ` (${code})` : ''}`;
  }
}

/** mkdir -p with an actionable error on failure. */
function mkdirSafe(dir: string): void {
  try {
    mkdirSync(dir, { recursive: true });
  } catch (e: any) {
    throw new Error(describeFsError(e, dir, 'creating output directory'));
  }
}

/**
 * writeFileSync with an actionable error on failure. Used for every evidence
 * file + summary so a full disk / bad perms produces a clear message instead
 * of an opaque stack trace mid-run.
 */
function writeFileSafe(path: string, data: string): void {
  try {
    writeFileSync(path, data);
  } catch (e: any) {
    throw new Error(describeFsError(e, path, 'writing'));
  }
}

/**
 * Wrap a set of Findings (from a signal module) into a schema-valid PROCESS/HYBRID
 * EvidenceFile keyed to an anchor requirement id, pulling metadata from the registry.
 */
function wrapSignalEvidence(
  reqId: string, findings: ProviderBlock['findings'], tier: ImpactTier, runId: string, frmrVersion: string,
): EvidenceFile {
  const reg = getRequirement(reqId);
  const ap = reg ? appliesAtLevel(reg, tier) : null;
  const providers: ProviderBlock[] = [{ provider: 'aws', account_id: null, region_set: [], evidence: [], findings, warnings: [] }];
  return {
    ksi_id: reqId,
    ksi_name: reg?.name ?? reqId,
    ksi_statement: reg?.statement ?? ap?.statement ?? reqId,
    scope: 'HYBRID',
    frmr_version: frmrVersion,
    run_id: runId,
    collected_at: new Date().toISOString(),
    providers,
    rollup: makeRollup(providers),
    nist_controls: reg?.controls,
    category: reg?.category ?? 'frr-requirement',
    family: reg?.family,
    impact_level: tier,
    applicable_key_word: ap?.key_word ?? undefined,
    level_source: ap?.source,
    actor_scope: 'provider',
    awareness_only: false,
    summary_for_llm: `${reqId} automated signal: ${findings.filter((f) => f.passed).length}/${findings.length} check(s) passed at ${tier}.`,
  };
}

/**
 * Run the ADS / MAS / SCG automated-signal modules when their inputs are
 * configured (env-gated; absent input → skipped). Returns the evidence files +
 * the requirement ids they cover (so the process-artifact emitter skips them).
 * READ-ONLY: ADS does outbound GET probes; MAS/SCG read operator-provided files.
 */
async function emitSignalEvidence(
  outDir: string, tier: ImpactTier, runId: string, frmrVersion: string,
): Promise<{ results: RunResult[]; coveredIds: Set<string> }> {
  const results: RunResult[] = [];
  const coveredIds = new Set<string>();
  const write = (reqId: string, findings: ProviderBlock['findings'], source: string) => {
    if (findings.length === 0) return;
    const evf = wrapSignalEvidence(reqId, findings, tier, runId, frmrVersion);
    const validation = validateEvidenceFile(JSON.parse(JSON.stringify(evf)));
    const outPath = resolve(outDir, `${reqId}.json`);
    writeFileSafe(outPath, JSON.stringify(evf, null, 2));
    coveredIds.add(reqId);
    results.push({
      ksi_id: reqId, evidence_file: outPath, rollup_pass: evf.rollup.pass,
      findings_count: evf.rollup.passing_findings + evf.rollup.failing_findings,
      warnings_count: 0, duration_ms: 0, schema_valid: validation.valid,
      schema_errors: validation.valid ? undefined : formatErrors(validation.errors),
    });
    console.log(`  [${reqId}] ${source} signal emitted (${evf.rollup.pass ? '✓ PASS' : '✗ FAIL'})`);
  };

  // ADS — public Trust Center / CSO / OSCAL endpoint probe.
  try {
    const urls = adsUrlsFromEnv();
    if (urls.length > 0) {
      const probe = await probeAdsEndpoints({ urls });
      write('ADS-CSO-PUB', buildAdsFindings(probe, tier), 'ADS endpoint probe');
    }
  } catch (e: any) { console.error(`  ADS probe failed: ${e?.message ?? e}`); }

  // MAS — documented assessment scope vs discovered inventory.
  try {
    const docPath = process.env.CLOUD_EVIDENCE_MAS_DOCUMENTED_PATH;
    if (docPath && existsSync(docPath)) {
      const documented: string[] = JSON.parse(readFileSync(docPath, 'utf8'));
      // Discovered: an explicit file, else best-effort from the inventory evidence.
      let discovered: string[] = [];
      const discPath = process.env.CLOUD_EVIDENCE_MAS_DISCOVERED_PATH;
      if (discPath && existsSync(discPath)) {
        discovered = JSON.parse(readFileSync(discPath, 'utf8'));
      } else {
        const invPath = resolve(outDir, 'KSI-PIY-GIV.json');
        if (existsSync(invPath)) {
          try {
            const inv = JSON.parse(readFileSync(invPath, 'utf8'));
            for (const p of inv.providers ?? []) for (const f of p.findings ?? []) {
              for (const r of f.gap?.affected_resources ?? []) if (r.identifier) discovered.push(r.identifier);
            }
          } catch { /* best-effort */ }
        }
      }
      if (Array.isArray(documented)) {
        const recon = reconcileMas({ documented, discovered });
        write('MAS-CSO-IIR', buildMasFindings(recon, tier), 'MAS reconciliation');
      }
    }
  } catch (e: any) { console.error(`  MAS reconcile failed: ${e?.message ?? e}`); }

  // SCG — published Secure Configuration Guide vs observed config.
  try {
    const guidePath = process.env.CLOUD_EVIDENCE_SCG_GUIDE_PATH;
    if (guidePath) {
      const { baseline, error } = loadScgBaseline(guidePath);
      if (!error) {
        let observed: Record<string, unknown> = {};
        const obsPath = process.env.CLOUD_EVIDENCE_SCG_OBSERVED_PATH;
        if (obsPath && existsSync(obsPath)) {
          try { observed = JSON.parse(readFileSync(obsPath, 'utf8')); } catch { /* */ }
        }
        const cmp = compareScg({ guide: baseline, observed });
        write('SCG-CSO-RSC', buildScgFindings(cmp, tier), 'SCG comparison');
      } else {
        console.error(`  SCG guide load: ${error}`);
      }
    }
  } catch (e: any) { console.error(`  SCG compare failed: ${e?.message ?? e}`); }

  return { results, coveredIds };
}

/**
 * Load the operator's attestation register (proof that process requirements are
 * met). Optional — absent file means "no attestations yet". Accepts either an
 * array of records (each with requirement_id) or an object keyed by requirement_id.
 * Read-only; never written.
 */
function loadAttestations(path: string | null): Record<string, AttestationRecord> {
  if (!path) return {};
  if (!existsSync(path)) {
    console.warn(`[attestations] register not found at ${path}; process requirements will report as not-yet-attested.`);
    return {};
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e: any) {
    console.error(`[attestations] ${path} is not valid JSON: ${e?.message ?? e}. Ignoring.`);
    return {};
  }
  const out: Record<string, AttestationRecord> = {};
  if (Array.isArray(raw)) {
    for (const r of raw) if (r && typeof r === 'object' && (r as any).requirement_id) out[(r as any).requirement_id] = r as AttestationRecord;
  } else if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (v && typeof v === 'object') out[k] = { requirement_id: k, ...(v as object) } as AttestationRecord;
    }
  }
  return out;
}

interface Config {
  frmr_version: string;
  /** FedRAMP impact tier to evaluate against. CLI --impact-level overrides this. */
  impact_level?: ImpactTier;
  aws: { enabled: boolean; regions: string[]; prod_tag?: { key: string; values: string[] } };
  gcp: { enabled: boolean; organization_id: string | null; projects: string[]; prod_label?: { key: string; values: string[] } };
  azure?: { enabled: boolean; subscriptions: string[]; tenant_id?: string | null; prod_tag?: { key: string; values: string[] } };
  output_dir: string;
  /**
   * SA-9 Subprocessor Inventory source (LOOP-J.J2). Either-or, not exclusive:
   * a Google-Sheet (`spreadsheet_id` + `sheet_range` + `columns`) and/or a local
   * YAML/JSON `config_path`. Both can run and merge (config wins on a name conflict).
   */
  subprocessors?: {
    config_path?: string;
    spreadsheet_id?: string;
    sheet_range?: string;
    columns?: { name: number } & Record<string, number>;
  };
  /**
   * Configuration Management Plan operator config (LOOP-C.C1). Consumed only
   * when --cmp is set. CLI flags / env vars take precedence over these values.
   */
  cmp?: {
    approval_narrative?: string;
    rollback_authority?: string;
    change_windows?: string;
    baseline_config_href?: string;
    ccb_roster?: CmpCcbRosterEntry[];
    tooling?: CmpTooling[];
  };
  /**
   * Information System Contingency Plan operator config (LOOP-C.C2). Consumed
   * only when --iscp / --iscp-test-aar is set. CLI flags / env vars take
   * precedence over these values.
   */
  iscp?: {
    rto?: { hours: number; rationale: string };
    rpo?: { hours: number; rationale: string };
    recovery_priority?: 'mission-critical' | 'mission-essential' | 'standard';
    alternate_site?: { type: 'hot' | 'warm' | 'cold' | 'cloud'; location: string; activation_procedure: string };
    activation_authority?: string;
    activation_criteria?: string[];
    cp_coordinator?: { name: string; org: string; email: string; phone: string };
    team_roster?: IscpTeamMember[];
    vendor_contacts?: IscpVendorContact[];
    backup_strategy_summary?: string;
    /** CP-4 test After-Action Report input. */
    test?: {
      test_date?: string;
      test_type?: 'tabletop' | 'functional' | 'full-interruption';
      participants?: IscpTestParticipant[];
      scenarios?: IscpTestScenario[];
      lessons_learned?: IscpTestLessonLearned[];
      test_coordinator?: string;
    };
  };
  /**
   * Incident Response Plan operator config (LOOP-C.C3). Consumed only when
   * --irp / --irp-test-aar is set. CLI flags / env vars take precedence.
   */
  irp?: {
    spec_version?: IrpSpecVersion;
    team_roster?: IrpTeamMember[];
    escalation?: IrpEscalationRule[];
    external_contacts?: IrpExternalContact[];
    communications?: IrpCommunicationsPlan;
    classification_levels?: IrpClassificationLevel[];
    /** IR-3 test After-Action Report input. */
    test?: {
      test_date?: string;
      test_type?: 'tabletop' | 'functional' | 'red-team';
      participants?: IrpTestParticipant[];
      scenarios?: IrpTestScenario[];
      lessons_learned?: IrpTestLessonLearned[];
      test_coordinator?: string;
    };
  };
}

function loadConfig(path: string): Config {
  if (!existsSync(path)) {
    throw new Error(`Config not found at ${path}. Copy config.yaml.example and edit it.`);
  }
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e: any) {
    throw new Error(`Cannot read config ${path}: ${e.message}`);
  }
  let parsed: any;
  try {
    parsed = parseYaml(raw);
  } catch (e: any) {
    throw new Error(`Config ${path} is not valid YAML: ${e.message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`Config ${path} did not parse to an object`);
  }
  // Light shape validation — enough to fail fast on typos.
  const errors: string[] = [];
  if (typeof parsed.frmr_version !== 'string' || !parsed.frmr_version) {
    errors.push('frmr_version (string) is required');
  }
  if (!parsed.aws || typeof parsed.aws !== 'object') {
    errors.push('aws (object) is required');
  } else {
    if (typeof parsed.aws.enabled !== 'boolean') errors.push('aws.enabled must be boolean');
    if (parsed.aws.enabled && (!Array.isArray(parsed.aws.regions) || parsed.aws.regions.length === 0)) {
      errors.push('aws.regions must be a non-empty array when aws.enabled is true');
    }
  }
  if (!parsed.gcp || typeof parsed.gcp !== 'object') {
    errors.push('gcp (object) is required');
  } else {
    if (typeof parsed.gcp.enabled !== 'boolean') errors.push('gcp.enabled must be boolean');
    if (parsed.gcp.enabled && !Array.isArray(parsed.gcp.projects)) {
      errors.push('gcp.projects must be an array (may be empty) when gcp.enabled is true');
    }
  }
  // azure is optional (omit → disabled; introduced in AZ-1 so existing configs keep working).
  if (parsed.azure !== undefined && parsed.azure !== null) {
    if (typeof parsed.azure !== 'object') errors.push('azure must be an object when present');
    else {
      if (typeof parsed.azure.enabled !== 'boolean') errors.push('azure.enabled must be boolean');
      if (parsed.azure.enabled && !Array.isArray(parsed.azure.subscriptions)) {
        errors.push('azure.subscriptions must be an array (may be empty) when azure.enabled is true');
      }
    }
  }
  if (parsed.impact_level != null && !['low', 'moderate', 'high'].includes(String(parsed.impact_level))) {
    errors.push(`impact_level must be one of: low, moderate, high (got: ${parsed.impact_level})`);
  }
  if (errors.length > 0) {
    throw new Error(`Config ${path} has validation errors:\n  - ${errors.join('\n  - ')}`);
  }
  return parsed as Config;
}

interface RunResult {
  ksi_id: string;
  evidence_file: string;
  rollup_pass: boolean;
  findings_count: number;
  warnings_count: number;
  duration_ms: number;
  schema_valid: boolean;
  schema_errors?: string;
  /** True for requirements that obligate FedRAMP/agency/3PAO (not the provider). */
  awareness_only?: boolean;
  /** Third-party tools detected by this KSI's collectors (aggregated for process satisfiers). */
  detected_tools?: ThirdPartyToolMatch[];
}

async function runOneKsi(
  ksi: KsiEntry,
  config: Config,
  args: Args,
  runId: string,
  awsAccount: string | null,
  impactLevel: ImpactTier,
  awsTargets: FanoutTarget[] | null = null,
  ledger?: RunLedger,
  adaptive?: AdaptiveLimiter,
): Promise<RunResult> {
  const startedAt = Date.now();
  const ksiLog = logger({ ksi: ksi.id, run_id: runId });
  ksiLog.debug({ event: 'ksi.start', scope: ksi.scope });
  const providers: ProviderBlock[] = [];

  if (args.providers.includes('aws') && config.aws.enabled && ksi.aws) {
    const region = config.aws.regions[0] ?? 'us-east-1';
    // In fanout mode we iterate every target; otherwise we just hit the
    // single default-credentials account.
    const targets: Array<{ accountId: string | null; auth: any }> = awsTargets
      ? awsTargets.filter((t) => t.auth !== null).map((t) => ({ accountId: t.account_id, auth: t.auth! }))
      : [{ accountId: awsAccount, auth: undefined }];
    for (const t of targets) {
      const startedAt = Date.now();
      try {
        const block = await ksi.aws({ aws: { region, account_id: t.accountId, auth: t.auth } });
        providers.push(block);
        adaptive?.onSuccess('aws');
        ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'aws', account_id: t.accountId, status: 'ok', duration_ms: Date.now() - startedAt });
      } catch (e: any) {
        const klass = classifyError(e);
        if (klass === 'throttling') adaptive?.onThrottle('aws');
        ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'aws', account_id: t.accountId, status: 'fail', duration_ms: Date.now() - startedAt, err_class: klass, err_message: e?.message });
        const warning = diagnoseAwsError(
          e,
          `aws:${ksi.id}`,
          klass === 'access_denied' ? 'IAM Read-Only-Access + scoped extras (see RUNBOOK §2.1)' : '(see warning)',
        );
        ksiLog.error({
          event: 'collector.fail',
          provider: 'aws', ksi_id: ksi.id, account_id: t.accountId, region,
          err_name: e?.name, err_message: e?.message, err_class: klass,
        });
        providers.push({
          provider: 'aws',
          account_id: t.accountId,
          region_set: [region],
          evidence: [],
          findings: [],
          warnings: [warning],
        });
      }
    }
  }

  if (args.providers.includes('gcp') && config.gcp.enabled && ksi.gcp) {
    for (const project of config.gcp.projects) {
      const startedAt = Date.now();
      try {
        const block = await ksi.gcp({ gcp: { project_id: project } });
        providers.push(block);
        adaptive?.onSuccess('gcp');
        ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'gcp', project_id: project, status: 'ok', duration_ms: Date.now() - startedAt });
      } catch (e: any) {
        const klass = classifyError(e);
        if (klass === 'throttling') adaptive?.onThrottle('gcp');
        ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'gcp', project_id: project, status: 'fail', duration_ms: Date.now() - startedAt, err_class: klass, err_message: e?.message });
        const warning = diagnoseGcpError(
          e,
          `gcp:${ksi.id}`,
          klass === 'access_denied' ? 'roles/viewer + roles/iam.securityReviewer (see RUNBOOK §2.2)' : '(see warning)',
        );
        ksiLog.error({
          event: 'collector.fail',
          provider: 'gcp', ksi_id: ksi.id, project_id: project,
          err_name: e?.name, err_message: e?.message, err_class: klass,
        });
        providers.push({
          provider: 'gcp',
          project_id: project,
          evidence: [],
          findings: [],
          warnings: [warning],
        });
      }
    }
  }

  if (args.providers.includes('azure') && config.azure?.enabled && ksi.azure) {
    // Most Azure IAM / AAD reads are tenant-scoped, not subscription-scoped, so
    // we make ONE call per KSI (not one per subscription). Resource-scoped Azure
    // collectors (added later) can iterate config.azure.subscriptions themselves.
    const startedAt = Date.now();
    try {
      const block = await ksi.azure({ azure: { tenant_id: config.azure.tenant_id ?? null, subscription_id: config.azure.subscriptions[0] ?? null, subscription_ids: config.azure.subscriptions ?? [] } });
      providers.push(block);
      adaptive?.onSuccess('azure');
      ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'azure', status: 'ok', duration_ms: Date.now() - startedAt });
    } catch (e: any) {
      const klass = classifyError(e);
      if (klass === 'throttling') adaptive?.onThrottle('azure');
      ledger?.record('collector.run', { ksi_id: ksi.id, provider: 'azure', status: 'fail', duration_ms: Date.now() - startedAt, err_class: klass, err_message: e?.message });
      ksiLog.error({
        event: 'collector.fail',
        provider: 'azure', ksi_id: ksi.id,
        err_name: e?.name, err_message: e?.message, err_class: klass,
      });
      const reqRole = klass === 'access_denied'
        ? 'Reader + the Microsoft Graph *.Read.All scopes the collector needs (see RUNBOOK §2.3 / IAM-PERMISSIONS-CATALOG.md)'
        : '(see warning)';
      providers.push({
        provider: 'azure',
        account_id: null,
        evidence: [],
        findings: [],
        warnings: [`azure:${ksi.id}: ${e?.message ?? e} — required: ${reqRole}`],
      });
    }
  }

  const rollup = makeRollup(providers);
  const summary_for_llm = buildSummaryForLlm(ksi, providers, rollup);
  // Resolve impact-tier metadata from the requirement registry (if this KSI is in it).
  const regEntry = getRequirement(ksi.id);
  const ap = regEntry ? appliesAtLevel(regEntry, impactLevel) : null;
  const envelope: EvidenceFile = {
    ksi_id: ksi.id,
    ksi_name: ksi.name,
    ksi_statement: ksi.statement,
    scope: ksi.scope,
    frmr_version: config.frmr_version,
    run_id: runId,
    collected_at: new Date().toISOString(),
    providers,
    rollup,
    process_artifacts_required: ksi.process_artifacts_required,
    nist_controls: ksi.nist_controls,
    related_ksis: relatedKsisFor(ksi.id),
    summary_for_llm,
    category: regEntry?.category ?? 'ksi-indicator',
    family: regEntry?.family,
    impact_level: impactLevel,
    applicable_key_word: ap?.key_word ?? undefined,
    level_source: ap?.source,
    actor_scope: regEntry ? actorScopeOf(regEntry) : 'provider',
    awareness_only: false,
  };

  // Round-trip through JSON so the validator sees the exact shape that will
  // be persisted (Dates → strings, undefineds dropped). This catches bugs
  // where a collector returned a Date object the SDK gave us instead of an
  // ISO string, or where a required field was set to undefined.
  const serialized = JSON.parse(JSON.stringify(envelope));
  const validation = validateEvidenceFile(serialized);

  const outPath = resolve(args.outDir, `${ksi.id}.json`);
  writeFileSafe(outPath, JSON.stringify(envelope, null, 2));

  const duration_ms = Date.now() - startedAt;
  ksiLog.info({
    event: 'ksi.complete',
    rollup_pass: envelope.rollup.pass,
    passing: envelope.rollup.passing_findings,
    failing: envelope.rollup.failing_findings,
    warnings: envelope.rollup.warnings.length,
    schema_valid: validation.valid,
    duration_ms,
  });

  return {
    ksi_id: ksi.id,
    evidence_file: outPath,
    rollup_pass: envelope.rollup.pass,
    findings_count: envelope.rollup.passing_findings + envelope.rollup.failing_findings,
    warnings_count: envelope.rollup.warnings.length,
    duration_ms,
    schema_valid: validation.valid,
    schema_errors: validation.valid ? undefined : formatErrors(validation.errors),
    detected_tools: providers.flatMap((p) => p.third_party_tools_detected ?? []),
  };
}

export async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const config = loadConfig(args.configPath);
  const runId = randomUUID();
  const startedAt = new Date().toISOString();
  // Resolve the impact tier: CLI flag > config > default 'moderate'.
  const impactLevel: ImpactTier = args.impactLevel ?? config.impact_level ?? 'moderate';

  mkdirSafe(args.outDir);

  // ---- Production hardening: run lock (no overlapping runs into the same out dir)
  // + append-only run ledger (every action persisted) + adaptive throttle tracking. ----
  let runLock: RunLock | null = null;
  if (!args.dryRun) {
    try {
      runLock = acquireRunLock(args.outDir, runId);
    } catch (e) {
      if (e instanceof RunLockHeldError) { console.error(e.message); process.exitCode = 1; return; }
      throw e;
    }
    // Guarantee the lock is freed on ANY process exit (incl. early returns / errors).
    process.once('exit', () => runLock?.release());
  }
  const ledger = createRunLedger(resolve(args.outDir, 'run-ledger.jsonl'), runId);
  const adaptive = new AdaptiveLimiter();
  ledger.record('run.start', { status: 'info', impact_level: impactLevel, providers: args.providers.join(',') });

  // ---- Load plugins (must happen BEFORE we resolve the in-scope KSI list) ----
  if (args.pluginsDir) {
    const pl = await loadPlugins(args.pluginsDir);
    console.log(`Plugins: ${summarizePluginLoad(pl)} (from ${args.pluginsDir})`);
    for (const failure of pl.failures) console.error(`  ! plugin failed: ${failure.path}: ${failure.error}`);
  }

  const inScopeKsis = args.ksiFilter
    ? args.ksiFilter.map((id) => KSI_MAP[id]).filter((k): k is KsiEntry => !!k)
    : SUPPORTED_KSIS.map((id) => KSI_MAP[id]).filter((k): k is KsiEntry => !!k);

  console.log(`cloud-evidence run ${runId}`);
  console.log(`  impact level: ${impactLevel}${impactLevel === 'high' ? ' (High applicability DERIVED from NIST 800-53 Rev5)' : ''}`);
  if (impactLevel === 'high') {
    // FedRAMP 20x does NOT yet cover High impact: per fedramp.gov/20x/phases,
    // Phase 4 (Class D / High pilot) is scheduled FY27 Q1-Q2 and is still
    // future as of June 2026. The current 20x catalog (FRMR.documentation.json
    // v0.9.43-beta) authors only Low + Moderate KSI applicability. Running
    // with --impact-level high here means: KSI assertions still use the 20x
    // catalog as-is (Moderate semantics) and the impact-tier difference is
    // applied via NIST 800-53 Rev5 High baseline parameter overlays through
    // core/control-benchmark.ts — NOT via 20x-specific High obligations
    // (which the program has not authored yet). Audit packages produced at
    // this level should cite SP 800-53 Rev5 High as the authoritative
    // controlling baseline, not "FedRAMP 20x High" (which is not yet a
    // defined assessment scope).
    console.log('  ⚠ NOTICE: FedRAMP 20x Phase 4 (Class D / High pilot) is scheduled FY27 Q1-Q2');
    console.log('           and has not yet been published. High applicability here is sourced');
    console.log('           from the NIST 800-53 Rev5 High baseline parameter overlay, NOT from');
    console.log('           20x-specific High obligations. See docs/IMPACT-LEVEL-NOTES.md.');
  }
  console.log(`  benchmark framework: ${args.framework}${args.framework === 'rev5' ? ' (full NIST SP 800-53B baseline)' : ' (controls referenced by 20x KSIs)'}`);
  console.log(`  providers: ${args.providers.join(', ')}`);
  console.log(`  ksis (${inScopeKsis.length}): ${inScopeKsis.map((k) => k.id).join(', ')}`);
  console.log(`  out: ${args.outDir}`);
  console.log(`  dry-run: ${args.dryRun}`);
  console.log();
  log.info({
    event: 'run.start',
    run_id: runId,
    providers: args.providers,
    ksi_count: inScopeKsis.length,
    concurrency: args.concurrency,
    out_dir: args.outDir,
    dry_run: args.dryRun,
  });

  if (args.dryRun) {
    console.log('Dry run: showing collection plan, no SDK calls will be made.');
    for (const ksi of inScopeKsis) {
      const targets: string[] = [];
      if (args.providers.includes('aws') && config.aws.enabled && ksi.aws) targets.push('aws');
      if (args.providers.includes('gcp') && config.gcp.enabled && ksi.gcp) {
        for (const p of config.gcp.projects) targets.push(`gcp:${p}`);
      }
      console.log(`  ${ksi.id} [${ksi.scope}] → ${targets.join(', ') || '(no targets)'}`);
    }
    return;
  }

  // Verify credentials early
  let awsAccount: string | null = null;
  if (args.providers.includes('aws') && config.aws.enabled) {
    try {
      const region = config.aws.regions[0] ?? 'us-east-1';
      const me = await aws.whoAmI(aws.makeAwsAuth(region));
      awsAccount = me.account;
      console.log(`AWS authenticated as ${me.arn} (account ${me.account})`);
    } catch (e: any) {
      const klass = classifyError(e);
      console.error(`AWS auth failed (${klass}): ${e.message}`);
      if (klass === 'access_denied') {
        console.error('  → STS GetCallerIdentity returned 403/AccessDenied. Either:');
        console.error('    (a) your principal exists but lacks `sts:GetCallerIdentity` (rare — almost always default-allowed); or');
        console.error('    (b) an SCP / permissions boundary is denying you. Check the parent OU.');
      } else if (klass === 'network') {
        console.error('  → Network unreachable. Check VPN, proxy, or aws.amazonaws.com DNS.');
      } else {
        console.error('  → Most likely an expired session. Run one of:');
        console.error('      aws sso login                    # for SSO');
        console.error('      export AWS_PROFILE=<profile>     # for named profiles');
        console.error('      export AWS_ACCESS_KEY_ID=...     # for static creds (not recommended)');
      }
      args.providers = args.providers.filter((p) => p !== 'aws');
    }
  }
  if (args.providers.includes('gcp') && config.gcp.enabled) {
    try {
      const me = await whoAmIGcp();
      console.log(`GCP authenticated as ${me.principal}`);
    } catch (e: any) {
      const klass = classifyError(e);
      console.error(`GCP auth failed (${klass}): ${e.message}`);
      if (klass === 'access_denied') {
        console.error('  → ADC principal exists but lacks roles/serviceusage.serviceUsageConsumer on the project.');
      } else {
        console.error('  → ADC missing or expired. Run:');
        console.error('      gcloud auth application-default login');
        console.error('    OR for an impersonated service account:');
        console.error('      gcloud auth application-default login --impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com');
      }
      args.providers = args.providers.filter((p) => p !== 'gcp');
    }
  }
  if (args.providers.includes('azure') && config.azure?.enabled) {
    try {
      const me = await whoAmIAzure();
      console.log(`Azure authenticated as ${me.principal}${me.tenantId ? ` (tenant ${me.tenantId})` : ''}`);
    } catch (e: any) {
      console.error(`Azure auth failed: ${e?.message ?? e}`);
      console.error('  → No credential found in the DefaultAzureCredential chain. Run one of:');
      console.error('      az login                                          # local CLI session');
      console.error('      export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...   # service principal');
      console.error('    or run from an Azure resource with a Managed Identity attached.');
      args.providers = args.providers.filter((p) => p !== 'azure');
    }
  }
  if (args.providers.length === 0) {
    console.error('No providers available. Aborting.');
    process.exit(1);
  }

  // ---- Pre-validate integration env vars (fail fast before collection) ----
  // The audit found multiple integrations only checked their tokens after the
  // run completed, wasting compute when something was misconfigured.
  const missingEnv: Array<{ flag: string; envs: string[] }> = [];
  if (args.llmGeneratePrs && !process.env.ANTHROPIC_API_KEY) {
    missingEnv.push({ flag: '--llm-generate-prs', envs: ['ANTHROPIC_API_KEY'] });
  }
  if (args.ticketProvider === 'github' && (!process.env.GITHUB_TOKEN || !process.env.GITHUB_REPO)) {
    missingEnv.push({ flag: '--ticket-push github', envs: ['GITHUB_TOKEN', 'GITHUB_REPO'] });
  }
  if (args.ticketProvider === 'jira' && (!process.env.JIRA_SITE_URL || !process.env.JIRA_EMAIL || !process.env.JIRA_API_TOKEN || !process.env.JIRA_PROJECT_KEY)) {
    missingEnv.push({ flag: '--ticket-push jira', envs: ['JIRA_SITE_URL', 'JIRA_EMAIL', 'JIRA_API_TOKEN', 'JIRA_PROJECT_KEY'] });
  }
  if (args.ticketProvider === 'servicenow' && (!process.env.SERVICENOW_URL || !process.env.SERVICENOW_USER || !process.env.SERVICENOW_PASSWORD)) {
    missingEnv.push({ flag: '--ticket-push servicenow', envs: ['SERVICENOW_URL', 'SERVICENOW_USER', 'SERVICENOW_PASSWORD'] });
  }
  if (args.webhookUrl && !process.env.CLOUD_EVIDENCE_WEBHOOK_SECRET) {
    missingEnv.push({ flag: '--webhook-url', envs: ['CLOUD_EVIDENCE_WEBHOOK_SECRET'] });
  }
  if (args.pushParamify && !process.env.PARAMIFY_API_TOKEN) {
    missingEnv.push({ flag: '--push-paramify', envs: ['PARAMIFY_API_TOKEN'] });
  }
  if (args.pushTracker && !process.env.TRACKER_API_TOKEN) {
    missingEnv.push({ flag: '--push-tracker', envs: ['TRACKER_API_TOKEN'] });
  }
  if (missingEnv.length > 0) {
    console.error('Missing env vars for the requested integration flags:');
    for (const m of missingEnv) console.error(`  ${m.flag} requires ${m.envs.join(', ')}`);
    console.error('Aborting before collection to avoid wasting compute.');
    process.exit(1);
  }

  // ---- Build AWS Organizations fan-out plan ----
  let fanoutTargets: FanoutTarget[] | null = null;
  if (args.awsOrgFanout && args.providers.includes('aws') && config.aws.enabled) {
    try {
      const region = config.aws.regions[0] ?? 'us-east-1';
      const plan = await buildFanoutPlan({
        region,
        includeAccounts: args.awsFanoutInclude,
        excludeAccounts: args.awsFanoutExclude,
        roleName: args.awsCrossAccountRole ?? undefined,
      });
      fanoutTargets = plan.targets;
      console.log(`AWS fan-out: ${plan.total_discovered} discovered, ${plan.targets.length} targeted${plan.skipped.length ? `, ${plan.skipped.length} skipped` : ''}`);
      if (plan.skipped.length > 0) {
        for (const s of plan.skipped.slice(0, 10)) {
          console.log(`  skipped ${s.account_id}: ${s.reason}`);
        }
        if (plan.skipped.length > 10) console.log(`  …and ${plan.skipped.length - 10} more`);
      }
    } catch (e: any) {
      console.error(`AWS fan-out plan failed (continuing with single account): ${e.message}`);
      log.error({ event: 'fanout.plan_failed', err_message: e?.message });
    }
  }
  console.log();

  // Run KSIs in parallel with a concurrency cap. AWS / GCP rate limits make
  // unbounded parallelism risky (throttling cascades), so we cap at
  // args.concurrency (default 4). Each KSI's internal SDK calls remain serial
  // within its collector; the speedup comes from overlapping idle time
  // (network I/O, paginators waiting on the next page) across KSIs.
  const limit = pLimit(Math.max(1, args.concurrency));
  console.log(`Running ${inScopeKsis.length} KSIs with concurrency=${args.concurrency}...`);
  const tasks = inScopeKsis.map((ksi) =>
    limit(async () => {
      const res = await runOneKsi(ksi, config, args, runId, awsAccount, impactLevel, fanoutTargets, ledger, adaptive);
      const verdict = res.rollup_pass ? '✓ PASS' : '✗ FAIL';
      const warn = res.warnings_count > 0 ? ` (${res.warnings_count} warning${res.warnings_count > 1 ? 's' : ''})` : '';
      const schemaTag = res.schema_valid ? '' : ' ⚠ schema-invalid';
      console.log(`  [${res.ksi_id}] ${verdict} ${res.findings_count} finding${res.findings_count === 1 ? '' : 's'}${warn}${schemaTag} · ${res.duration_ms}ms`);
      if (!res.schema_valid && res.schema_errors) {
        console.error(`    schema errors for ${res.ksi_id}:\n${res.schema_errors}`);
      }
      return res;
    }),
  );
  const results: RunResult[] = await Promise.all(tasks);

  // ---- Emit automated ADS / MAS / SCG signal evidence (env-gated) BEFORE the
  // process-artifact emitter, so those requirement ids get the real signal rather
  // than a process stub. ----
  let signalCoveredIds = new Set<string>();
  if (!args.ksiFilter) {
    try {
      const sig = await emitSignalEvidence(args.outDir, impactLevel, runId, config.frmr_version);
      results.push(...sig.results);
      signalCoveredIds = sig.coveredIds;
    } catch (e: any) {
      console.error(`Signal-evidence emission failed: ${e?.message ?? e}`);
    }
  }

  // ---- Emit PROCESS-scope evidence for in-scope requirements WITHOUT a cloud
  // collector (the ~99 governance/process requirements + level-scoped FRR items).
  // Skipped when --ksis filters to a specific KSI subset. ----
  if (!args.ksiFilter) {
    try {
      const attestations = loadAttestations(process.env.CLOUD_EVIDENCE_ATTESTATIONS ?? null);
      // Aggregate third-party tools detected across all collectors (dedupe by name)
      // so the process tracker can flip matching alternative_satisfiers to detected.
      const detectedTools = Array.from(
        new Map(results.flatMap((r) => r.detected_tools ?? []).map((t) => [t.name, t])).values(),
      );
      const sel = selectForLevel(impactLevel);
      const alreadyWritten = new Set<string>([...inScopeKsis.map((k) => k.id), ...signalCoveredIds, 'KSI-AFR-PVA', 'KSI-CSX-SUM']);
      const toEmit: RequirementEntry[] = [...sel.inScope, ...sel.awareness]
        .filter((r) => !alreadyWritten.has(r.id) && !KSI_MAP[r.id]);
      let emitted = 0;
      let awarenessCount = 0;
      for (const req of toEmit) {
        const ev = buildProcessArtifactEvidence(req, {
          tier: impactLevel, runId, frmrVersion: config.frmr_version, attestations,
          playbooks: REQUIREMENT_PLAYBOOKS, detectedTools,
        });
        const validation = validateEvidenceFile(JSON.parse(JSON.stringify(ev)));
        const outPath = resolve(args.outDir, `${req.id}.json`);
        writeFileSafe(outPath, JSON.stringify(ev, null, 2));
        if (ev.awareness_only) awarenessCount++;
        results.push({
          ksi_id: req.id,
          evidence_file: outPath,
          // Awareness items always "pass" (not the provider's to satisfy); they
          // are excluded from the provider gap count in the summary below.
          rollup_pass: ev.rollup.pass,
          findings_count: ev.rollup.passing_findings + ev.rollup.failing_findings,
          warnings_count: 0,
          duration_ms: 0,
          schema_valid: validation.valid,
          schema_errors: validation.valid ? undefined : formatErrors(validation.errors),
          awareness_only: ev.awareness_only,
        });
        emitted++;
      }
      console.log(`Process requirements [${impactLevel}]: emitted ${emitted} evidence file(s) (${awarenessCount} awareness-only) for requirements without a cloud collector.`);
    } catch (e: any) {
      console.error(`Process-requirement emission failed: ${e?.message ?? e}`);
    }
  }

  // ---- FedRAMP reference-architecture audit (Coalfire RAMPpak-derived hardening
  // expectations). Emitted as AUDIT-REFARCH-{AWS,GCP}.json so the findings flow into
  // the NIST 800-53 benchmark, family roll-up, crosswalk, OSCAL, and the signed
  // manifest (all of which scan out/ below). These are hardening audits, NOT KSI
  // obligations, so they are intentionally NOT pushed into `results` / the KSI
  // pass-fail rollup. Runs BEFORE those consumers read the output dir. ----
  if (args.referenceArch && !args.dryRun) {
    const refCtx = { runId, frmrVersion: config.frmr_version };
    if (args.providers.includes('aws') && config.aws.enabled) {
      try {
        const region = config.aws.regions[0] ?? 'us-east-1';
        const ev = await collectAwsReferenceArch(aws.makeAwsAuth(region), awsAccount, refCtx);
        writeFileSafe(resolve(args.outDir, 'AUDIT-REFARCH-AWS.json'), JSON.stringify(ev, null, 2));
        const total = ev.rollup.passing_findings + ev.rollup.failing_findings;
        console.log(`Reference-arch (AWS): ${ev.rollup.passing_findings}/${total} checks pass → AUDIT-REFARCH-AWS.json` +
          (ev.rollup.warnings.length ? ` · ${ev.rollup.warnings.length} warning(s)` : ''));
        for (const w of ev.rollup.warnings) console.error(`  ! refarch(aws): ${w}`);
        ledger.record('reference_arch.aws', { status: 'info', pass: ev.rollup.passing_findings, fail: ev.rollup.failing_findings, warnings: ev.rollup.warnings.length });
      } catch (e: any) {
        console.error(`Reference-arch (AWS) failed: ${e?.message ?? e}`);
        log.error({ event: 'reference_arch.aws.fail', err_message: e?.message });
      }
    }
    if (args.providers.includes('gcp') && config.gcp.enabled && config.gcp.projects.length > 0) {
      try {
        const blocks: ProviderBlock[] = [];
        const warnings: string[] = [];
        let template: EvidenceFile | null = null;
        let idx = 0;
        for (const project of config.gcp.projects) {
          // Org-scoped checks run only on the first project; later projects skip
          // them (organizationId=null) so org-level findings aren't duplicated.
          const ev = await collectGcpReferenceArch(project, { ...refCtx, organizationId: idx === 0 ? config.gcp.organization_id : null });
          template ??= ev;
          blocks.push(...ev.providers);
          warnings.push(...ev.rollup.warnings);
          idx++;
        }
        if (template) {
          const passing = blocks.reduce((a, b) => a + b.findings.filter((f) => f.passed).length, 0);
          const failing = blocks.reduce((a, b) => a + b.findings.filter((f) => !f.passed).length, 0);
          const merged: EvidenceFile = {
            ...template,
            providers: blocks,
            rollup: { pass: failing === 0, passing_findings: passing, failing_findings: failing, warnings, missing_evidence: [], alternatives_in_play: 0 },
          };
          writeFileSafe(resolve(args.outDir, 'AUDIT-REFARCH-GCP.json'), JSON.stringify(merged, null, 2));
          console.log(`Reference-arch (GCP): ${passing}/${passing + failing} checks pass across ${config.gcp.projects.length} project(s) → AUDIT-REFARCH-GCP.json` +
            (warnings.length ? ` · ${warnings.length} warning(s)` : ''));
          for (const w of warnings) console.error(`  ! refarch(gcp): ${w}`);
          ledger.record('reference_arch.gcp', { status: 'info', pass: passing, fail: failing, projects: config.gcp.projects.length, warnings: warnings.length });
        }
      } catch (e: any) {
        console.error(`Reference-arch (GCP) failed: ${e?.message ?? e}`);
        log.error({ event: 'reference_arch.gcp.fail', err_message: e?.message });
      }
    }
    if (args.providers.includes('azure') && config.azure?.enabled) {
      try {
        const subs = config.azure.subscriptions ?? [];
        const ev = await collectAzureReferenceArch(subs, refCtx);
        writeFileSafe(resolve(args.outDir, 'AUDIT-REFARCH-AZURE.json'), JSON.stringify(ev, null, 2));
        const total = ev.rollup.passing_findings + ev.rollup.failing_findings;
        console.log(`Reference-arch (Azure): ${ev.rollup.passing_findings}/${total} checks pass across ${subs.length} subscription(s) → AUDIT-REFARCH-AZURE.json` +
          (ev.rollup.warnings.length ? ` · ${ev.rollup.warnings.length} warning(s)` : ''));
        for (const w of ev.rollup.warnings) console.error(`  ! refarch(azure): ${w}`);
        ledger.record('reference_arch.azure', { status: 'info', pass: ev.rollup.passing_findings, fail: ev.rollup.failing_findings, subscriptions: subs.length, warnings: ev.rollup.warnings.length });
      } catch (e: any) {
        console.error(`Reference-arch (Azure) failed: ${e?.message ?? e}`);
        log.error({ event: 'reference_arch.azure.fail', err_message: e?.message });
      }
    }
  }

  const invalidCount = results.filter((r) => !r.schema_valid).length;
  if (invalidCount > 0) {
    console.error();
    console.error(`Schema validation: ${invalidCount} of ${results.length} evidence file(s) failed validation.`);
    if (args.strictSchema) {
      console.error('--strict-schema set; aborting before integrations.');
      process.exitCode = 2;
      return;
    }
  } else {
    console.log(`Schema validation: all ${results.length} evidence file(s) valid.`);
  }

  // ---- Phase 5: emit KSI-AFR-PVA and KSI-CSX-SUM meta evidence ----
  const summaryPathPrev = resolve(args.outDir, 'pva-run-summary.json');
  const previousRunPath = existsSync(summaryPathPrev) ? summaryPathPrev : undefined;
  try {
    const { evidence: pvaEvidence } = buildPvaEvidence({
      outDir: args.outDir,
      runId,
      startedAt,
      finishedAt: new Date().toISOString(),
      frmrVersion: config.frmr_version,
      previousRunPath,
    });
    writeFileSafe(resolve(args.outDir, 'KSI-AFR-PVA.json'), JSON.stringify(pvaEvidence, null, 2));
    console.log(`  [KSI-AFR-PVA] meta-collector emitted (${pvaEvidence.rollup.pass ? '✓ PASS' : '✗ FAIL'})`);
  } catch (e: any) {
    console.error(`  [KSI-AFR-PVA] failed: ${e.message}`);
  }
  try {
    const summariesDir = resolve(args.outDir, '..', 'summaries');
    const { summaries, markdownFiles } = buildCsxSum({
      outDir: args.outDir,
      summariesDir,
      frmrVersion: config.frmr_version,
    });
    console.log(`  [KSI-CSX-SUM] aggregator emitted ${markdownFiles} markdown file(s) at ${summariesDir} (${summaries.length} KSI summaries).`);
  } catch (e: any) {
    console.error(`  [KSI-CSX-SUM] failed: ${e.message}`);
  }

  // ---- NIST 800-53 control benchmark (computed here so a compact headline can
  // ride along in the run summary; the full report is written below, before
  // signing, so it's covered by the manifest). ----
  let benchmark: import('./control-benchmark.ts').ControlBenchmark | null = null;
  try {
    benchmark = buildControlBenchmark(args.outDir, { framework: args.framework, level: impactLevel });
  } catch (e: any) {
    console.error(`Control benchmark failed: ${e?.message ?? e}`);
    log.error({ event: 'control_benchmark.fail', err_message: e?.message });
  }

  // Emit pva-run-summary.json
  const finishedAt = new Date().toISOString();
  const summary = {
    run_id: runId,
    started_at: startedAt,
    finished_at: finishedAt,
    frmr_version: config.frmr_version,
    providers_used: args.providers,
    aws_account_id: awsAccount,
    gcp_projects: config.gcp.projects,
    results,
    impact_level: impactLevel,
    framework: args.framework,
    // Compact control-benchmark headline for downstream consumers (the tracker).
    // The full per-control report is control-benchmark.json.
    control_benchmark: benchmark
      ? { framework: benchmark.framework, impact_level: benchmark.impact_level, control_source: benchmark.control_source, totals: benchmark.totals }
      : null,
    rollup: {
      // The provider's own requirements (excludes awareness items that obligate
      // FedRAMP / an agency / a 3PAO — those can't be "failed" by the provider).
      total_requirements: results.filter((r) => !r.awareness_only).length,
      /** Back-compat alias for total_requirements (was total_ksis before level coverage). */
      total_ksis: results.filter((r) => !r.awareness_only).length,
      passed: results.filter((r) => !r.awareness_only && r.rollup_pass).length,
      failed: results.filter((r) => !r.awareness_only && !r.rollup_pass).length,
      awareness_tracked: results.filter((r) => r.awareness_only).length,
      total_warnings: results.reduce((a, r) => a + r.warnings_count, 0),
      // Explicit lists so a reader (or downstream automation) doesn't have to
      // re-derive which requirements failed / failed schema validation from `results`.
      failed_ksis: results.filter((r) => !r.awareness_only && !r.rollup_pass).map((r) => r.ksi_id),
      schema_invalid_ksis: results.filter((r) => r.schema_valid === false).map((r) => r.ksi_id),
    },
    // Production-hardening telemetry.
    throttle_events: adaptive.throttleSnapshot(),
    ledger: { path: ledger.path, records: ledger.count(), write_failures: ledger.writeFailures() },
  };
  const summaryPath = resolve(args.outDir, 'pva-run-summary.json');
  writeFileSafe(summaryPath, JSON.stringify(summary, null, 2));
  ledger.record('run.complete', {
    status: 'info',
    total: summary.rollup.total_requirements,
    passed: summary.rollup.passed,
    failed: summary.rollup.failed,
    throttles: Object.values(adaptive.throttleSnapshot()).reduce((a, b) => a + b, 0),
  });

  // ---- Family roll-up: per-family posture across all emitted evidence ----
  try {
    const rollupResult = buildFamilyRollup(args.outDir);
    writeFileSafe(resolve(args.outDir, 'family-rollup.json'), JSON.stringify(rollupResult, null, 2));
    const worst = [...rollupResult.families].filter((f) => f.failed > 0).sort((a, b) => a.pass_rate - b.pass_rate).slice(0, 5);
    console.log(`Family roll-up: ${rollupResult.families.length} families, ${Math.round(rollupResult.totals.pass_rate * 100)}% provider pass rate` +
      (worst.length ? ` (lowest: ${worst.map((f) => `${f.family} ${Math.round(f.pass_rate * 100)}%`).join(', ')})` : ''));
  } catch (e: any) {
    console.error(`Family roll-up failed: ${e?.message ?? e}`);
  }

  // ---- NIST 800-53 control benchmark (written BEFORE signing so it's covered
  // by the manifest). The object was computed above the summary; here we just
  // persist the full per-control report and log/record the headline. ----
  if (benchmark) {
    try {
      writeFileSafe(resolve(args.outDir, 'control-benchmark.json'), JSON.stringify(benchmark, null, 2));
      const t = benchmark.totals;
      console.log(
        `Control benchmark [${benchmark.framework} / ${impactLevel}]: ` +
          `${t.satisfied}/${t.in_scope} controls satisfied ` +
          `(${Math.round(t.baseline_coverage_rate * 100)}% baseline coverage, ` +
          `${Math.round(t.assessed_pass_rate * 100)}% of assessed; ` +
          `${t.not_assessed} not-assessed)`,
      );
      ledger.record('control_benchmark.complete', {
        status: 'info',
        framework: benchmark.framework,
        impact_level: impactLevel,
        in_scope: t.in_scope,
        satisfied: t.satisfied,
        not_assessed: t.not_assessed,
      });
    } catch (e: any) {
      console.error(`Control benchmark write failed: ${e?.message ?? e}`);
      log.error({ event: 'control_benchmark.write_fail', err_message: e?.message });
    }
  }

  // ---- FedRAMP Integrated Inventory Workbook (written BEFORE signing) ----
  let inventorySummary: Record<string, unknown> | null = null;
  if (args.inventoryWorkbook && !args.dryRun) {
    try {
      let assets: CloudAsset[] = [];
      const invWarnings: string[] = [];
      const sensitiveBuckets = new Set<string>();   // Macie-flagged S3 (across regions)
      if (args.providers.includes('aws') && config.aws.enabled) {
        // Sweep ALL configured regions; collect account-global services (S3,
        // CloudFront) only on the first region pass.
        const regions = config.aws.regions.length ? config.aws.regions : ['us-east-1'];
        let first = true;
        for (const region of regions) {
          const auth = aws.makeAwsAuth(region);
          // Backbone (breadth: all resource types) + per-service depth enrichers.
          const disc = await discoverAwsAssets(auth, awsAccount);
          assets.push(...disc.assets); invWarnings.push(...disc.warnings);
          const r = await collectAwsAssets(auth, awsAccount, { includeGlobal: first });
          assets.push(...r.assets); invWarnings.push(...r.warnings);
          const macie = await collectMacieSensitiveBuckets(auth);   // data classification
          for (const b of macie.buckets) sensitiveBuckets.add(b); invWarnings.push(...macie.warnings);
          first = false;
        }
        // Month-to-date cost by service (account-global; one call via us-east-1).
        try {
          const cost = await collectAwsCost(aws.makeAwsAuth(config.aws.regions[0] ?? 'us-east-1'));
          writeFileSafe(resolve(args.outDir, 'inventory-cost.json'), JSON.stringify(cost, null, 2));
          invWarnings.push(...cost.warnings);
        } catch (e: any) { invWarnings.push(`Cost summary: ${e.message}`); }
      }
      if (args.providers.includes('gcp') && config.gcp.enabled) {
        for (const project of config.gcp.projects) {
          const disc = await discoverGcpAssets(project);
          assets.push(...disc.assets); invWarnings.push(...disc.warnings);
          const r = await collectGcpAssets(project);
          assets.push(...r.assets); invWarnings.push(...r.warnings);
        }
      }
      if (args.providers.includes('azure') && config.azure?.enabled) {
        // Azure Resource Graph is multi-subscription: one query covers them all.
        const subs = config.azure.subscriptions ?? [];
        const disc = await discoverAzureAssets(subs);
        assets.push(...disc.assets); invWarnings.push(...disc.warnings);
        const r = await collectAzureAssets(subs);
        assets.push(...r.assets); invWarnings.push(...r.warnings);
      }
      // Merge duplicates (same resource seen by backbone + enricher / multiple passes).
      assets = dedupeAssets(assets);
      // FedPy-native enrichment: tags → owner/function/baseline; reconcile against
      // our own scan evidence (column O/I); cross-link each asset to the KSI
      // findings that touch it (Comments).
      for (const a of assets) {
        enrichFromTags(a);
        applyTagGovernance(a);             // env/criticality/cost-center + required-tag compliance
        a.endOfLife ??= deriveEol(a);      // lifecycle EOL from runtime/engine/OS
        applyDiagramLabelAndComments(a);   // INV-S6: column S synthesis + column T tag passthrough
      }
      applyDataClassification(assets, sensitiveBuckets);   // Macie-flagged S3 → dataClassification
      const invCtx = readInventoryContext(args.outDir);
      const scanned = reconcileScans(assets, invCtx.scannedIdentifiers);
      const linked = annotateWithFindings(assets, invCtx.findings);
      // Read the prior snapshot BEFORE overwriting it (change tracking).
      const prevAssets = readPreviousInventory(resolve(args.outDir, 'inventory.json'));
      // Rich superset JSON (source of truth) + relationship graph + projections.
      const edges = deriveEdges(assets);
      const snapshot = buildInventorySnapshot(assets, edges);
      writeInventoryJson(snapshot, resolve(args.outDir, 'inventory.json'));
      const oscalN = writeInventoryOscal(snapshot, resolve(args.outDir, 'inventory-oscal.json'));
      writeInventoryCmdb(snapshot, resolve(args.outDir, 'inventory-cmdb.json'));
      // INV-S1: per-run coverage report. Projects the asset list against the
      // 25-column Appendix M coverage contract (`inventory-coverage.ts`) so
      // the operator + CI see exactly which cells filled, per cloud.
      const coverage = emitInventoryCoverage(assets, resolve(args.outDir, 'inventory-coverage.json'));
      let invDelta = '';
      if (prevAssets) {
        const d = diffInventory(prevAssets, assets);
        writeInventoryDiff(d, resolve(args.outDir, 'inventory-diff.json'));
        invDelta = ` · Δ +${d.added.length}/-${d.removed.length}/~${d.changed.length}`;
      }
      const res = writeInventoryWorkbook(assets, {
        csvPath: resolve(args.outDir, 'inventory-workbook.csv'),
        xlsxPath: resolve(args.outDir, 'inventory-workbook.xlsx'),
      });
      inventorySummary = {
        asset_count: res.asset_count, row_count: res.row_count, edge_count: edges.length,
        in_scan: scanned, finding_linked: linked, oscal_items: oscalN,
        by_provider: snapshot.by_provider,
      };
      console.log(`Inventory: ${res.asset_count} asset(s) → ${res.row_count} row(s) ` +
        `(${scanned} in-scan, ${linked} linked to KSI findings, ${edges.length} edges)${invDelta} ` +
        `(inventory.json + workbook.{csv,xlsx} + oscal + cmdb)` +
        (invWarnings.length ? ` · ${invWarnings.length} warning(s)` : ''));
      console.log(`  Coverage: ${coverageSummary(coverage)}`);
      for (const w of invWarnings) console.error(`  ! inventory: ${w}`);
      ledger.record('inventory_workbook.complete', { status: 'info', assets: res.asset_count, rows: res.row_count, scanned, finding_linked: linked, edges: edges.length, warnings: invWarnings.length });
    } catch (e: any) {
      console.error(`Inventory workbook failed: ${e?.message ?? e}`);
      log.error({ event: 'inventory_workbook.fail', err_message: e?.message });
    }
  }
  // Re-write the run summary with the inventory headline so the tracker can
  // surface it (the summary was written above, before inventory ran).
  if (inventorySummary) {
    try { writeFileSafe(summaryPath, JSON.stringify({ ...summary, inventory: inventorySummary }, null, 2)); }
    catch (e: any) { log.error({ event: 'summary.rewrite_fail', err_message: e?.message }); }
  }

  console.log();
  console.log(`Run complete: ${summary.rollup.passed}/${summary.rollup.total_ksis} passing`);
  console.log(`Summary: ${summaryPath}`);
  log.info({
    event: 'run.complete',
    run_id: runId,
    started_at: startedAt,
    finished_at: finishedAt,
    total: summary.rollup.total_ksis,
    passed: summary.rollup.passed,
    failed: summary.rollup.failed,
    total_warnings: summary.rollup.total_warnings,
    invalid_evidence_files: results.filter((r) => !r.schema_valid).length,
  });

  // ---- Anomaly detection (must run BEFORE signing) ----
  if (args.anomaly) {
    try {
      const r = detectAnomalies({ outDir: args.outDir, runId, finishedAt });
      const types = Object.entries(r.summary.by_type).map(([t, n]) => `${t}=${n}`).join(' ');
      console.log(`Anomalies: ${r.summary.total} (${types || 'none'}) across ${r.window_runs}-run baseline`);
    } catch (e: any) {
      console.error(`Anomaly detection failed: ${e.message}`);
      log.error({ event: 'anomaly.fail', err_message: e?.message });
    }
  }

  // ---- SBOM parsing (must run BEFORE signing) ----
  if (args.sbomDir) {
    try {
      const r = buildSbomReport({ sbomDir: args.sbomDir, outPath: resolve(args.outDir, 'sbom-report.json') });
      console.log(`SBOM: ${r.summary.sbom_count} files, ${r.summary.unique_components} unique components, ${r.summary.critical_vulns + r.summary.high_vulns} critical/high vulns`);
    } catch (e: any) {
      console.error(`SBOM report failed: ${e.message}`);
      log.error({ event: 'sbom.fail', err_message: e?.message });
    }
  }

  // ---- Powerpipe mod (must run BEFORE signing so it's covered by the manifest) ----
  if (args.powerpipe) {
    try {
      const r = emitPowerpipeMod({ outDir: args.outDir });
      console.log(`Powerpipe: ${r.mod_dir} (${r.control_count} controls, ${r.benchmark_count} benchmarks across ${r.domain_count} domains)`);
    } catch (e: any) {
      console.error(`Powerpipe emission failed: ${e.message}`);
      log.error({ event: 'powerpipe.fail', err_message: e?.message });
    }
  }

  // ---- Crosswalk report (must run BEFORE signing so it's covered by the manifest) ----
  if (args.crosswalk) {
    try {
      const r = buildCrosswalkReport(args.outDir);
      const fws = r.framework_summaries.map((f) => `${f.framework}=${f.controls_referenced.length}`).join(' ');
      console.log(`Crosswalk: ${r.total_ksis_analyzed} KSIs analyzed, ${fws}${r.unmapped_nist_controls.length ? ` (${r.unmapped_nist_controls.length} unmapped controls)` : ''}`);
    } catch (e: any) {
      console.error(`Crosswalk emission failed: ${e.message}`);
      log.error({ event: 'crosswalk.fail', err_message: e?.message });
    }
  }

  // ---- OSCAL Assessment Results (must run BEFORE signing so it's covered by the manifest) ----
  if (args.oscal) {
    try {
      const r = emitOscalAssessmentResults({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        organizationName: args.oscalOrgName ?? undefined,
        // LOOP-A.A3: AR's mandatory import-ap resolves to local ap.json when
        // LOOP-A.A2 ran in this orchestrator invocation. Explicit override
        // via --ap-href would belong in args; for now the local-ap default
        // is sufficient because LOOP-A.A2 always emits to outDir/ap.json.
        strictChain: args.strictChain,
      });
      console.log(`OSCAL: ${r.path} (${r.result_count} results, ${r.finding_count} findings, ${r.observation_count} observations; import-ap=${r.ap_link ?? 'unknown'})`);
      // OSC-1: validate the emitted document against the committed NIST schema.
      const v = validateOscalFile(r.path, 'assessment-results');
      if (v.valid) {
        console.log('OSCAL schema validation: assessment-results.json is valid (NIST OSCAL 1.1.2).');
        ledger.record('oscal.validate', { status: 'info', valid: true, model: 'assessment-results' });
      } else {
        console.error(`OSCAL schema validation: ${v.errors.length} error(s)${v.schema_found ? '' : ' (schema not committed — run scripts/extract-oscal-schemas.mjs)'}`);
        for (const e of v.errors.slice(0, 10)) console.error(`  ! ${e}`);
        ledger.record('oscal.validate', { status: 'fail', valid: false, model: 'assessment-results', error_count: v.errors.length });
        log.warn({ event: 'oscal.invalid', error_count: v.errors.length });
        if (args.strictSchema && v.schema_found) process.exitCode = 2;
      }
    } catch (e: any) {
      console.error(`OSCAL emission failed: ${e.message}`);
      log.error({ event: 'oscal.fail', err_message: e?.message });
    }
  }

  // ---- SA-9 Subprocessor Inventory (LOOP-J.J2) — normalized, signed inventory
  // from an operator YAML/JSON config and/or the Google-Sheet reader. Runs
  // BEFORE the OSCAL SSP emitter (which reads subprocessor-inventory.json to
  // populate system-implementation.leveraged-authorizations[]) and BEFORE
  // signing so the inventory JSON + XLSX are covered by the run manifest. ----
  {
    const subCfgPath = args.subprocessorsConfig ?? config.subprocessors?.config_path ?? null;
    const subSheet = config.subprocessors?.spreadsheet_id
      ? {
          spreadsheet_id: config.subprocessors.spreadsheet_id,
          sheet_range: config.subprocessors.sheet_range ?? 'Sheet1!A1:Z',
          columns: config.subprocessors.columns ?? { name: 0 },
        }
      : undefined;
    if (!args.dryRun && (subCfgPath || subSheet)) {
      try {
        const resolvedCfg = subCfgPath ? resolve(process.cwd(), subCfgPath) : undefined;
        if (resolvedCfg && !existsSync(resolvedCfg)) {
          console.error(`Subprocessor inventory: config ${resolvedCfg} not found — skipping.`);
        } else {
          const r = await emitSubprocessorInventory({
            outDir: args.outDir,
            runId,
            configPath: resolvedCfg,
            sheetConfig: subSheet,
            systemId: args.systemId ?? undefined,
          });
          const c = r.inventory.coverage;
          console.log(
            `Subprocessor inventory: ${r.json_path} (${c.total_rows} row(s) · ` +
              `${c.tier_1_critical_count} T1 · ${c.tier_2_significant_count} T2 · ` +
              `${c.tier_3_routine_count} T3 · ${c.rows_with_fedramp_authorization} FedRAMP-auth` +
              `${c.rows_with_expired_soc2.length ? ` · ${c.rows_with_expired_soc2.length} expired-SOC2` : ''}` +
              `${r.requires_operator_input ? ' · ⚠ requires-operator-input' : ''})`,
          );
          ledger.record('subprocessor_inventory.emit', {
            status: 'info',
            rows: c.total_rows,
            tier_1: c.tier_1_critical_count,
            fedramp_authorized: c.rows_with_fedramp_authorization,
            expired_soc2: c.rows_with_expired_soc2.length,
            requires_operator_input: r.requires_operator_input,
          });
        }
      } catch (e: any) {
        console.error(`Subprocessor inventory failed: ${e.message}`);
        log.error({ event: 'subprocessor_inventory.fail', err_message: e?.message });
      }
    }
  }

  // ---- Supply-chain risk register (LOOP-J.J3) — SR-3 / NIST SP 800-161r1
  // C-SCRM Plan. Joins SBOM CVEs (sbom-report.json) + CISA KEV exposure +
  // subprocessor risk tiers (subprocessor-inventory.json) + operator-asserted
  // risks (--risks-config). Runs AFTER the SBOM + subprocessor passes and
  // BEFORE the OSCAL SSP/POA&M (which consume it) and before signing. ----
  if (args.supplyChainRisk && !args.dryRun) {
    try {
      const kevPath = process.env.CLOUD_EVIDENCE_KEV_PATH
        ?? (existsSync(resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json'))
          ? resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json')
          : undefined);
      const r = await emitSupplyChainRiskRegister({
        outDir: args.outDir,
        runId,
        systemId: args.systemId ?? undefined,
        kevCatalogPath: kevPath,
        risksConfigPath: args.risksConfig
          ? resolve(process.cwd(), args.risksConfig)
          : undefined,
      });
      const c = r.register.coverage;
      console.log(
        `Supply-chain risk: ${r.json_path} (${c.total_entries} entries · ` +
          `${c.open_critical + c.open_high} open C/H · ${c.kev_exposed} kev-exposed · ` +
          `${c.unsigned_sboms} unsigned-sbom · ${c.tier_1_critical_subprocessors} tier-1-subproc` +
          `${r.requires_operator_input.length ? ` · ${r.requires_operator_input.length} requires-operator-input` : ''})`,
      );
      ledger.record('supply_chain_risk.emit', {
        status: 'info',
        entries: c.total_entries,
        open_critical: c.open_critical,
        open_high: c.open_high,
        kev_exposed: c.kev_exposed,
        unsigned_sboms: c.unsigned_sboms,
        requires_operator_input: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`Supply-chain risk register failed: ${e.message}`);
      log.error({ event: 'supply_chain_risk.fail', err_message: e?.message });
    }
  }

  // ---- OSCAL System Security Plan (SSP-1) — draft, bootstrapped from evidence.
  // Runs BEFORE signing so it's covered by the manifest. ----
  if (args.oscalSsp) {
    try {
      const r = emitOscalSsp({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        organizationName: args.oscalOrgName ?? undefined,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        systemDescription: process.env.CLOUD_EVIDENCE_SYSTEM_DESCRIPTION ?? undefined,
        providers: args.providers,
      });
      console.log(`OSCAL SSP (draft): ${r.path} (${r.control_count} controls — ${r.implemented} implemented, ${r.partial} partial, ${r.planned} planned)`);
      const v = validateOscalFile(r.path, 'ssp');
      if (v.valid) {
        console.log('OSCAL schema validation: ssp.json is valid (NIST OSCAL 1.1.2).');
        ledger.record('oscal_ssp.validate', { status: 'info', valid: true, model: 'ssp', controls: r.control_count, implemented: r.implemented });
      } else {
        console.error(`OSCAL SSP schema validation: ${v.errors.length} error(s)${v.schema_found ? '' : ' (schema not committed — run scripts/extract-oscal-schemas.mjs)'}`);
        for (const e of v.errors.slice(0, 10)) console.error(`  ! ${e}`);
        ledger.record('oscal_ssp.validate', { status: 'fail', valid: false, model: 'ssp', error_count: v.errors.length });
        log.warn({ event: 'oscal_ssp.invalid', error_count: v.errors.length });
        if (args.strictSchema && v.schema_found) process.exitCode = 2;
      }
      // SSP-2: render the SSP to a FedRAMP-style Word document. The .docx itself is
      // not in the manifest (signer covers *.json only), but it's a faithful render of
      // the signed ssp.json — reproducible from the signed source.
      if (args.sspDocx) {
        try {
          const d = emitSspDocx({ outDir: args.outDir, sspPath: r.path });
          console.log(`OSCAL SSP (Word): ${d.path} (${(d.bytes / 1024).toFixed(0)} KB, ${d.control_count} controls)`);
          ledger.record('ssp_docx.emit', { status: 'info', bytes: d.bytes, controls: d.control_count });
        } catch (e: any) {
          console.error(`SSP Word render failed: ${e.message}`);
          log.error({ event: 'ssp_docx.fail', err_message: e?.message });
        }
      }
    } catch (e: any) {
      console.error(`OSCAL SSP emission failed: ${e.message}`);
      log.error({ event: 'oscal_ssp.fail', err_message: e?.message });
    }
  }

  // ---- OSCAL Assessment Plan (LOOP-A.A2) — the SAP draft. The AR will
  // Import-AP (LOOP-A.A3); the POA&M can reference its system-id alone OR
  // co-reference this AP via the SSP chain. Runs BEFORE signing so the AP
  // is covered by the run manifest. ----
  if (args.oscalAp) {
    try {
      const r = emitOscalAp({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        organizationName: args.oscalOrgName ?? undefined,
        thirdPartyAssessorName: args.thirdPartyAssessor ?? undefined,
        sspHref: args.oscalSsp ? 'ssp.json' : undefined,
        roeHref: args.apRoeHref ?? undefined,
        samplingMethodologyHref: args.apSamplingMethodologyHref ?? undefined,
        providers: args.providers,
      });
      console.log(
        `OSCAL AP (draft): ${r.path} (${r.reviewed_control_count} controls, ${r.activity_count} activities, ${r.assessment_subject_count} subjects, ${r.task_count} tasks)`
      );
      const v = validateOscalFile(r.path, 'assessment-plan');
      if (v.valid) {
        console.log('OSCAL schema validation: ap.json is valid (NIST OSCAL 1.1.2).');
        ledger.record('oscal_ap.validate', {
          status: 'info', valid: true, model: 'assessment-plan',
          controls: r.reviewed_control_count, activities: r.activity_count, tasks: r.task_count,
        });
      } else {
        console.error(`OSCAL AP schema validation: ${v.errors.length} error(s)${v.schema_found ? '' : ' (schema not committed — run scripts/extract-oscal-schemas.mjs)'}`);
        for (const e of v.errors.slice(0, 10)) console.error(`  ! ${e}`);
        ledger.record('oscal_ap.validate', { status: 'fail', valid: false, model: 'assessment-plan', error_count: v.errors.length });
        log.warn({ event: 'oscal_ap.invalid', error_count: v.errors.length });
        if (args.strictSchema && v.schema_found) process.exitCode = 2;
      }
    } catch (e: any) {
      console.error(`OSCAL AP emission failed: ${e.message}`);
      log.error({ event: 'oscal_ap.fail', err_message: e?.message });
    }
  }

  // ---- Rules of Engagement template seed (LOOP-A.A5) — Word .docx
  // pre-filled with system identity + boundary + IPs from real inventory +
  // scan windows + escalation contacts + controls-in-scope. The 3PAO
  // completes any REQUIRES-OPERATOR-INPUT markers and obtains signatures.
  // Runs BEFORE signing so the RoE is covered by the manifest. ----
  if (args.roe) {
    try {
      const r = emitRoeDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        cspOrganization: args.oscalOrgName ?? undefined,
        thirdPartyAssessor: args.thirdPartyAssessor ?? undefined,
        signedRoeHref: args.apRoeHref ?? undefined,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      console.log(
        `RoE (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.ip_count} IP rows, ${r.contact_count} contacts, ${r.scan_window_count} scan window(s); ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('roe.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        ip_count: r.ip_count,
        contact_count: r.contact_count,
        scan_window_count: r.scan_window_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`RoE emission failed: ${e.message}`);
      log.error({ event: 'roe.fail', err_message: e?.message });
    }
  }

  // ---- Configuration Management Plan (LOOP-C.C1) — an 11-section CM-9 Word
  // document (out/cmp.docx). The §4 Configuration Items table is auto-derived
  // from the real inventory.json (CM-8); the §7 Configuration Monitoring list
  // is derived from core/ksi-map.ts; process narratives (§3/§6/§8/§9/§10) fall
  // back to REQUIRES-OPERATOR-INPUT. CLI/env values override config.yaml:cmp.*.
  // Runs BEFORE signing so cmp.docx is covered by the submission bundle. ----
  if (args.cmp) {
    try {
      const r = emitCmpDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        cspOrganization: args.oscalOrgName ?? undefined,
        approvalWorkflowNarrative: args.cmpApprovalNarrative ?? config.cmp?.approval_narrative ?? undefined,
        rollbackAuthority: args.cmpRollbackAuthority ?? config.cmp?.rollback_authority ?? undefined,
        changeWindowsDescription: args.cmpChangeWindows ?? config.cmp?.change_windows ?? undefined,
        baselineConfigHref: args.cmpBaselineConfigHref ?? config.cmp?.baseline_config_href ?? undefined,
        ccbRoster: config.cmp?.ccb_roster ?? undefined,
        cmTooling: config.cmp?.tooling ?? undefined,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      console.log(
        `CMP (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.component_count} component(s), ${r.ksi_count} KSI domain(s); ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('cmp.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        component_count: r.component_count,
        ksi_count: r.ksi_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`CMP emission failed: ${e.message}`);
      log.error({ event: 'cmp.fail', err_message: e?.message });
    }
  }

  // ---- Information System Contingency Plan (LOOP-C.C2) — a CP-2/CP-9/CP-10
  // Word document (out/iscp.docx). The §4.2 Recovery-evidence table auto-fills
  // from the real signed RPL-family KSI files; Appendix B from the real
  // subprocessor inventory; recovery narratives fall back to
  // REQUIRES-OPERATOR-INPUT. Structured input comes from config.yaml:iscp.*;
  // CLI/env override. Runs BEFORE the AAR (which anchors to iscp.docx) + BEFORE
  // signing so both are covered by the submission bundle. ----
  if (args.iscp) {
    try {
      const ic = config.iscp;
      const rtoHours = args.iscpRtoHours ?? ic?.rto?.hours ?? null;
      const rpoHours = args.iscpRpoHours ?? ic?.rpo?.hours ?? null;
      const rto = rtoHours != null
        ? { hours: rtoHours, rationale: ic?.rto?.rationale ?? 'Operator-specified via --iscp-rto-hours.' }
        : undefined;
      const rpo = rpoHours != null
        ? { hours: rpoHours, rationale: ic?.rpo?.rationale ?? 'Operator-specified via --iscp-rpo-hours.' }
        : undefined;
      const r = emitIscpDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        cspOrganization: args.oscalOrgName ?? undefined,
        rto,
        rpo,
        recoveryPriority: ic?.recovery_priority,
        alternateSite: ic?.alternate_site
          ? { type: ic.alternate_site.type, location: ic.alternate_site.location, activationProcedure: ic.alternate_site.activation_procedure }
          : undefined,
        activationAuthority: ic?.activation_authority,
        activationCriteria: ic?.activation_criteria,
        cpCoordinator: ic?.cp_coordinator,
        teamRoster: ic?.team_roster,
        vendorContacts: ic?.vendor_contacts,
        backupStrategySummary: ic?.backup_strategy_summary,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      console.log(
        `ISCP (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.rpl_evidence_count} RPL evidence file(s), ${r.component_count} component(s), ${r.vendor_contact_count} vendor contact(s); ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('iscp.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        rpl_evidence_count: r.rpl_evidence_count,
        component_count: r.component_count,
        vendor_contact_count: r.vendor_contact_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`ISCP emission failed: ${e.message}`);
      log.error({ event: 'iscp.fail', err_message: e?.message });
    }
  }

  // ---- Contingency Plan Test After-Action Report (LOOP-C.C2) — a CP-4 Word
  // document (out/iscp-test-aar.docx). Test scenarios + lessons learned are
  // operator-supplied (config.yaml:iscp.test.*) — never fabricated; the report
  // anchors to out/iscp.docx (the plan under test) when it was emitted this run.
  // Runs BEFORE signing so it is covered by the submission bundle. ----
  if (args.iscpTestAar) {
    try {
      const t = config.iscp?.test;
      const r = emitIscpTestAarDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        testDate: args.iscpTestDate ?? t?.test_date ?? undefined,
        testType: (args.iscpTestType as 'tabletop' | 'functional' | 'full-interruption' | null) ?? t?.test_type ?? undefined,
        participants: t?.participants,
        scenarios: t?.scenarios,
        lessonsLearned: t?.lessons_learned,
        testCoordinator: t?.test_coordinator,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      console.log(
        `ISCP Test AAR (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.scenario_count} scenario(s), ${r.failed_scenario_count} failed, ${r.poam_candidate_count} POA&M candidate(s); ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('iscp-test-aar.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        scenario_count: r.scenario_count,
        failed_scenario_count: r.failed_scenario_count,
        poam_candidate_count: r.poam_candidate_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`ISCP Test AAR emission failed: ${e.message}`);
      log.error({ event: 'iscp-test-aar.fail', err_message: e?.message });
    }
  }

  // ---- Incident Response Plan (LOOP-C.C3) — an IR-8/IR-3/IR-4/IR-6 Word
  // document (out/irp.docx), structured per NIST SP 800-61 Rev. 3 (CSF 2.0
  // phases). §4 Detect auto-fills from the real KSI-INR-RIR evidence; §9
  // Reporting SLAs come from the FedRAMP Incident Communications Procedures;
  // team roster + communications plan fall back to REQUIRES-OPERATOR-INPUT.
  // Structured input comes from config.yaml:irp.*; CLI/env override. Runs after
  // the ISCP emit + before the IRP AAR (which anchors to irp.docx) + before
  // signing so all are covered by the submission bundle. ----
  if (args.irp) {
    try {
      const ip = config.irp;
      const r = emitIrpDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        impactLevel,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        cspOrganization: args.oscalOrgName ?? undefined,
        specVersion: (args.irpSpecVersion as IrpSpecVersion | null) ?? ip?.spec_version ?? undefined,
        irTeamRoster: ip?.team_roster,
        escalationMatrix: ip?.escalation,
        externalContacts: ip?.external_contacts,
        communicationsPlan: ip?.communications,
        classificationLevels: ip?.classification_levels,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      const cov = r.detection_coverage_percent != null ? `${r.detection_coverage_percent}% detection coverage` : 'no INR-RIR evidence';
      console.log(
        `IRP (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.detection_source_count} detection source(s), ${cov}; ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('irp.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        detection_source_count: r.detection_source_count,
        detection_coverage_percent: r.detection_coverage_percent,
        team_member_count: r.team_member_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`IRP emission failed: ${e.message}`);
      log.error({ event: 'irp.fail', err_message: e?.message });
    }
  }

  // ---- Incident Response Test After-Action Report (LOOP-C.C3) — an IR-3 Word
  // document (out/irp-test-aar.docx). Test scenarios + the 5-phase timing matrix
  // + lessons learned are operator-supplied (config.yaml:irp.test.*) — never
  // fabricated; the report anchors to out/irp.docx (the plan under test) when it
  // was emitted this run. Runs before signing so it is covered by the bundle. ----
  if (args.irpTestAar) {
    try {
      const t = config.irp?.test;
      const r = emitIrpTestAarDocx({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        testDate: t?.test_date ?? undefined,
        testType: t?.test_type ?? undefined,
        participants: t?.participants,
        scenarios: t?.scenarios,
        lessonsLearned: t?.lessons_learned,
        testCoordinator: t?.test_coordinator,
      });
      const sig = r.ready_for_signature ? '✓ ready for signature' : `⚠ ${r.requires_operator_input.length} operator input(s) needed`;
      console.log(
        `IRP Test AAR (draft): ${r.path} (${(r.bytes / 1024).toFixed(0)} KB, ${r.scenario_count} scenario(s), ${r.failed_scenario_count} failed, ${r.poam_candidate_count} POA&M candidate(s); ${sig})`
      );
      if (!r.ready_for_signature) {
        console.log(`  Operator inputs still needed: ${r.requires_operator_input.join(', ')}`);
      }
      ledger.record('irp-test-aar.emit', {
        status: 'info',
        ready_for_signature: r.ready_for_signature,
        scenario_count: r.scenario_count,
        failed_scenario_count: r.failed_scenario_count,
        poam_candidate_count: r.poam_candidate_count,
        requires_operator_input_count: r.requires_operator_input.length,
      });
    } catch (e: any) {
      console.error(`IRP Test AAR emission failed: ${e.message}`);
      log.error({ event: 'irp-test-aar.fail', err_message: e?.message });
    }
  }

  // ---- Per-finding composite risk scoring (LOOP-B.B1) — CVSS + EPSS +
  // inventory-derived criticality + exposure. Rewrites each KSI-*.json envelope
  // in place with a finding.risk_score block and emits out/risk-scores.json.
  // Runs BEFORE the OSCAL POA&M emitter (so the scores flow onto poam-item
  // props) and BEFORE signing (so risk-scores.json + the cache are covered by
  // the run manifest). EPSS hits the live FIRST API unless --risk-no-epss. ----
  if (args.riskScore) {
    try {
      const r = await emitRiskScores({
        outDir: args.outDir,
        runId,
        riskConfigPath: args.riskConfigPath
          ?? (existsSync(resolve(process.cwd(), 'risk-config.yaml')) ? resolve(process.cwd(), 'risk-config.yaml') : undefined),
        epssEnabled: args.riskNoEpss ? false : undefined,
      });
      console.log(
        `Risk scores: ${r.path} (${r.scored_findings} scored, ${r.unscored_findings} unscored; ` +
        `${r.cve_lookups} CVE(s): ${r.epss_cache_hits} cache hit(s), ${r.epss_api_calls} EPSS API call(s))`
      );
      ledger.record('risk_score.emit', {
        status: 'info',
        scored_findings: r.scored_findings,
        unscored_findings: r.unscored_findings,
        cve_lookups: r.cve_lookups,
        epss_cache_hits: r.epss_cache_hits,
        epss_api_calls: r.epss_api_calls,
      });
    } catch (e: any) {
      console.error(`Risk scoring failed: ${e.message}`);
      log.error({ event: 'risk_score.fail', err_message: e?.message });
    }
  }

  // ---- LOOP-B.B3: pull signed risk acceptances from the tracker (if configured)
  // BEFORE the POA&M emit, so approved+unexpired acceptances flip matching risks
  // to deviation-approved. When --pull-risk-acceptances is unset, the POA&M
  // emitter falls back to any cached out/.risk-acceptances.json snapshot (so
  // air-gapped runs work); absent that, every risk stays open — never silent. ----
  if (args.trackerUrl) {
    if (!args.trackerApiToken) {
      console.error('--pull-risk-acceptances requires --tracker-api-token (or CLOUD_EVIDENCE_TRACKER_TOKEN).');
      process.exitCode = 2;
    } else {
      try {
        const pulled = await pullActiveAcceptances(args.trackerUrl, args.trackerApiToken, args.outDir);
        console.log(`Risk acceptances: pulled ${pulled.length} approved record(s) from ${args.trackerUrl} → out/.risk-acceptances.json`);
        ledger.record('risk_acceptances.pull', { status: 'ok', count: pulled.length });
      } catch (e: any) {
        // Non-fatal: fall back to any cached snapshot. The POA&M emit still runs.
        console.warn(`Risk-acceptance pull failed (${e?.message ?? e}); using cached snapshot if present.`);
        log.warn({ event: 'risk_acceptances.pull_failed', err: String(e) });
        ledger.record('risk_acceptances.pull', { status: 'info', reason: String(e?.message ?? e) });
      }
    }
  }

  // ---- LOOP-B.B4: pull signed compensating controls from the tracker (if
  // configured) BEFORE the POA&M emit, so each approved acceptance's cited
  // compensating controls fill the matching risk's remediations[] (completed).
  // Defaults to the same tracker URL as the risk-acceptance pull; falls back to
  // any cached out/.compensating-controls.json snapshot when unreachable. ----
  const ccUrl = args.compensatingControlsUrl ?? args.trackerUrl;
  if (ccUrl) {
    if (!args.trackerApiToken) {
      console.error('--pull-compensating-controls requires --tracker-api-token (or CLOUD_EVIDENCE_TRACKER_TOKEN).');
      process.exitCode = 2;
    } else {
      try {
        const pulled = await pullCompensatingControls(ccUrl, args.trackerApiToken, args.outDir);
        console.log(`Compensating controls: pulled ${pulled.length} active record(s) from ${ccUrl} → out/.compensating-controls.json`);
        ledger.record('compensating_controls.pull', { status: 'ok', count: pulled.length });
      } catch (e: any) {
        console.warn(`Compensating-control pull failed (${e?.message ?? e}); using cached snapshot if present.`);
        log.warn({ event: 'compensating_controls.pull_failed', err: String(e) });
        ledger.record('compensating_controls.pull', { status: 'info', reason: String(e?.message ?? e) });
      }
    }
  }

  // ---- OSCAL Plan of Action & Milestones (LOOP-A.A1) — one poam-item per
  // failing finding, with FedRAMP-deadline math. Runs BEFORE signing so the
  // POA&M is covered by the run manifest. Skipped automatically when there
  // are zero failing findings (the OSCAL v1.1.2 schema mandates
  // poam-items.minItems=1 — emitter returns a structured "skipped" result). ----
  if (args.oscalPoam) {
    try {
      // LOOP-B.B2: load the CISA KEV catalog so the deadline engine can honour
      // per-CVE BOD 22-01 dueDates. Offline-first (committed catalog / env path).
      const kevPathPoam = process.env.CLOUD_EVIDENCE_KEV_PATH
        ?? (existsSync(resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json'))
          ? resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json')
          : undefined);
      const kevCatPoam = await loadKevCatalog({ path: kevPathPoam });
      const poamEmitArgs = {
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        systemName: args.systemName ?? undefined,
        systemId: args.systemId ?? undefined,
        // import-ssp.href wired iff the SSP was also emitted this run.
        ssp: args.oscalSsp ? { href: 'ssp.json', remarks: 'Local OSCAL SSP emitted in same run.' } : undefined,
        // back-matter reference to the signed manifest. After signing runs
        // below, the manifest path is well-known.
        signedManifestHref: args.noSign ? undefined : 'manifest.json',
        // LOOP-B.B2: KEV index for the priority-cascading deadline engine.
        kevIndex: kevCatPoam.count > 0 ? kevCatPoam.byCve : undefined,
      };
      // LOOP-E.E2: in monthly ConMon mode, route through runPoamMonthly() — it
      // threads the prior month's metadata.revisions[] forward, re-emits the
      // POA&M, computes the month-over-month delta (poam-delta-<YYYY-MM>.md),
      // archives the document, and appends the poam-ledger. The underlying
      // PoamEmitResult drives the same downstream validation/logging below.
      let monthly: PoamMonthlyResult | null = null;
      let r: PoamEmitResult;
      if (args.conmonMonthly) {
        const month = args.conmonMonth ?? new Date().toISOString().slice(0, 7);
        monthly = runPoamMonthly({ ...poamEmitArgs, reportMonth: month });
        r = monthly.emit;
      } else {
        r = emitOscalPoam(poamEmitArgs);
      }
      // LOOP-B.B2: --strict-risk fails the run if any deadline used the
      // observable severity-fallback (a sign the FedRAMP CMP table didn't load).
      if (r.path !== null && args.strictRisk && (r.deadline_fallback_count ?? 0) > 0) {
        console.error(
          `--strict-risk: ${r.deadline_fallback_count} finding(s) fell through to deadline severity-fallback ` +
            `(FedRAMP CMP table not loaded — see deadline-audit.json). Failing the run.`,
        );
        log.error({ event: 'strict_risk.fallback', count: r.deadline_fallback_count });
        process.exitCode = 5;
      }
      if (r.path !== null && (r.deadline_fallback_count ?? 0) === 0) {
        const auditN = r.deadline_audit?.length ?? 0;
        if (auditN > 0) console.log(`  Deadline audit: ${auditN} finding(s) → deadline-audit.json (0 severity-fallback)`);
      }
      if (r.path === null) {
        console.log(`OSCAL POA&M: skipped — ${r.skipped_reason} (this is a clean state, not a failure).`);
        ledger.record('oscal_poam.skip', { status: 'info', reason: r.skipped_reason ?? 'unknown' });
      } else {
        const sev = r.by_severity;
        console.log(
          `OSCAL POA&M: ${r.path} (${r.poam_item_count} items: ${sev.critical}C/${sev.high}H/${sev.medium}M/${sev.low}L/${sev.info}I; ${r.risk_count} risks, ${r.observation_count} observations)`
        );
        const v = validateOscalFile(r.path, 'poam');
        if (v.valid) {
          console.log('OSCAL schema validation: poam.json is valid (NIST OSCAL 1.1.2).');
          ledger.record('oscal_poam.validate', { status: 'info', valid: true, model: 'poam', items: r.poam_item_count });
        } else {
          console.error(`OSCAL POA&M schema validation: ${v.errors.length} error(s)${v.schema_found ? '' : ' (schema not committed — run scripts/extract-oscal-schemas.mjs)'}`);
          for (const e of v.errors.slice(0, 10)) console.error(`  ! ${e}`);
          ledger.record('oscal_poam.validate', { status: 'fail', valid: false, model: 'poam', error_count: v.errors.length });
          log.warn({ event: 'oscal_poam.invalid', error_count: v.errors.length });
          if (args.strictSchema && v.schema_found) process.exitCode = 2;
        }
      }
      // LOOP-E.E2: report the monthly delta + version-chain threading.
      if (monthly && monthly.delta) {
        const d = monthly.delta;
        console.log(
          `POA&M monthly delta (${monthly.delta.report_month}` +
            `${monthly.priorMonth ? ` vs ${monthly.priorMonth}` : ', first month'}): ` +
            `${d.added.length} added, ${d.closed.length} closed, ${d.status_changed.length} status, ` +
            `${d.past_deadline_items.length} past deadline → ${monthly.deltaPath}`,
        );
        ledger.record('poam_monthly.delta', {
          status: 'info',
          report_month: d.report_month,
          prior_month: monthly.priorMonth ?? 'none',
          added: d.added.length,
          closed: d.closed.length,
          status_changed: d.status_changed.length,
          severity_changed: d.severity_changed.length,
          past_deadline: d.past_deadline_items.length,
        });
      } else if (monthly && monthly.poamPath === null) {
        console.log(`POA&M monthly: skipped — ${monthly.skipped_reason} (clean state; no ledger entry written).`);
        ledger.record('poam_monthly.skip', { status: 'info', reason: monthly.skipped_reason ?? 'unknown' });
      }
    } catch (e: any) {
      console.error(`OSCAL POA&M emission failed: ${e.message}`);
      log.error({ event: 'oscal_poam.fail', err_message: e?.message });
    }
  }

  // ---- LOOP-B.B5: Central Risk Register (RA-3). Pull operator-entered
  // organisational risks from the tracker (if configured), then aggregate the
  // just-emitted POA&M risks (B.B1+B.B2) + cached signed acceptances (B.B3) +
  // compensating controls (B.B4) + organisational risks into a signed
  // out/risk-register.json + out/risk-register.xlsx. Runs AFTER the POA&M emit
  // (which it reads) and BEFORE signing so both artifacts are covered by the run
  // manifest. Air-gapped runs use whatever cached snapshots exist — never
  // fabricates a risk. ----
  if (args.riskRegister) {
    const orgUrl = args.organisationalRisksUrl ?? args.trackerUrl;
    if (orgUrl) {
      if (!args.trackerApiToken) {
        console.error('--pull-organisational-risks requires --tracker-api-token (or CLOUD_EVIDENCE_TRACKER_TOKEN).');
        process.exitCode = 2;
      } else {
        try {
          const pulled = await pullOrganisationalRisks(orgUrl, args.trackerApiToken, args.outDir);
          console.log(`Organisational risks: pulled ${pulled.length} record(s) from ${orgUrl} → out/.organisational-risks.json`);
          ledger.record('organisational_risks.pull', { status: 'ok', count: pulled.length });
        } catch (e: any) {
          console.warn(`Organisational-risk pull failed (${e?.message ?? e}); using cached snapshot if present.`);
          log.warn({ event: 'organisational_risks.pull_failed', err: String(e) });
          ledger.record('organisational_risks.pull', { status: 'info', reason: String(e?.message ?? e) });
        }
      }
    }
    try {
      const rr = emitRiskRegister({ outDir: args.outDir, runId });
      console.log(
        `Risk register: ${rr.jsonPath} (${rr.entries_total} entries: ` +
        `${rr.entries_by_source.finding} finding / ${rr.entries_by_source.acceptance} acceptance / ` +
        `${rr.entries_by_source.organisational} organisational; ${rr.open_count} open, ` +
        `${rr.high_inherent_count} high-inherent) + ${rr.xlsxPath}`,
      );
      ledger.record('risk_register.emit', {
        status: 'info',
        entries_total: rr.entries_total,
        finding: rr.entries_by_source.finding,
        acceptance: rr.entries_by_source.acceptance,
        organisational: rr.entries_by_source.organisational,
        open_count: rr.open_count,
        high_inherent_count: rr.high_inherent_count,
      });
    } catch (e: any) {
      console.error(`Risk register emission failed: ${e.message}`);
      log.error({ event: 'risk_register.fail', err_message: e?.message });
    }
  }

  // ---- Prohibited-vendor catalog (LOOP-W.W1) — merge OFAC SDN + BIS Entity
  // List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA
  // into one signed canonical-JSON catalog. Runs BEFORE signing so the catalog
  // is covered by the run manifest, and is the substrate the (future) W.W2
  // subprocessor screen reads. Network feeds are staged offline by
  // scripts/extract-prohibited-vendors.mjs; this pass ingests the snapshot +
  // the committed statutory constants (the offline-first path). ----
  if (args.prohibitedVendorsCatalog) {
    try {
      const cat = await emitProhibitedVendorsCatalog({
        outDir: args.outDir,
        configPath: existsSync(resolve(process.cwd(), 'prohibited-vendors-config.yaml'))
          ? resolve(process.cwd(), 'prohibited-vendors-config.yaml')
          : undefined,
      });
      const stats = cat.statistics;
      console.log(
        `Prohibited-vendor catalog: ${cat.catalog_path} (${cat.entity_count} entities from ${cat.source_count} source(s); ` +
        `${stats.duplicates_collapsed} dup(s) collapsed, ${stats.requires_operator_input_count} requires-operator-input` +
        `${cat.ephemeral_key ? '; ephemeral signing key' : ''})`
      );
      ledger.record('prohibited_vendors.emit', {
        status: 'info',
        entity_count: cat.entity_count,
        source_count: cat.source_count,
        duplicates_collapsed: stats.duplicates_collapsed,
        requires_operator_input_count: stats.requires_operator_input_count,
      });
    } catch (e: any) {
      console.error(`Prohibited-vendor catalog emission failed: ${e.message}`);
      log.error({ event: 'prohibited_vendors.fail', err_message: e?.message });
    }
  }

  // ---- Prohibited-vendor screen (LOOP-W.W2) — screen the subprocessor sheet +
  // SBOM (transitively) + OCI publishers + inventory provider tags against the
  // W.W1 catalog. Runs AFTER the catalog (which it consumes) and BEFORE signing
  // so the screen result is covered by the run manifest. FAR 52.204-25 applies
  // to every federal acquisition since 2020-08-13. The screen NEVER auto-submits
  // anything to a federal endpoint — it produces the evidence; the operator
  // submits (W.W3/W.W4 own the report + representation). ----
  if (args.prohibitedVendorScreen && !args.dryRun) {
    try {
      const overridesPath = resolve(process.cwd(), 'prohibited-vendors-overrides.yaml');
      // Best-effort: reuse the J.J2 subprocessor inventory rows as surface 1.
      let subprocessorRows: Array<{ name: string }> | undefined;
      let subprocessorSourcePath: string | undefined;
      const subInvPath = resolve(args.outDir, 'subprocessor-inventory.json');
      if (existsSync(subInvPath)) {
        try {
          const doc = JSON.parse(readFileSync(subInvPath, 'utf8'));
          const rows = (doc?.subprocessors ?? doc?.entries ?? doc?.rows ?? []) as any[];
          subprocessorRows = rows
            .map((r) => ({ name: String(r?.name ?? r?.vendor ?? '').trim() }))
            .filter((r) => r.name);
          subprocessorSourcePath = subInvPath;
        } catch { /* malformed inventory → screen the other surfaces */ }
      }
      const screen = emitProhibitedVendorsScreen({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        overridesPath: existsSync(overridesPath) ? overridesPath : undefined,
        subprocessorRows,
        subprocessorSourcePath,
        sbomDir: args.sbomDir ?? undefined,
        sbomMaxDepth: args.sbomMaxDepth,
        // OCI attestation dir + inventory.json are auto-detected under outDir.
      });
      const r = screen.result;
      console.log(
        `Prohibited-vendor screen: ${screen.json_path} (${r.summary.total_matches} match(es) across ` +
        `${r.surfaces_screened.length} surface(s); reportable_far=${r.reportable_under_far_52_204_25_d}, ` +
        `reportable_ndaa=${r.reportable_under_ndaa_1634}, reasonable_inquiry=${r.reasonable_inquiry_attested})`
      );
      ledger.record('prohibited_vendor_screen.emit', {
        status: 'info',
        total_matches: r.summary.total_matches,
        surfaces_walked: screen.surfaces_walked,
        reportable_far: r.reportable_under_far_52_204_25_d,
        reportable_ndaa: r.reportable_under_ndaa_1634,
      });
    } catch (e: any) {
      console.error(`Prohibited-vendor screen failed: ${e.message}`);
      log.error({ event: 'prohibited_vendor_screen.fail', err_message: e?.message });
    }
  }

  // ---- FAR 52.204-25(d) 1-business-day reporter (LOOP-W.W3) — ingest the W.W2
  // screen result, compose a signed report (JSON + .docx) per reportable
  // (match × affected contract), compute the federal-business-day deadline per
  // 5 U.S.C. §6103, and record each emission in the append-only ledger. Runs
  // AFTER the W.W2 screen (which it consumes) and BEFORE signing so the reports
  // are covered by the run manifest. The reporter NEVER auto-transmits to a
  // federal endpoint — it produces the artifact pair; the operator transmits. ----
  if (args.prohibitedVendor1bdReport && !args.dryRun) {
    try {
      const s889 = (config as any)?.section_889 ?? {};
      const signing = s889?.signing ?? {};
      const contactsPath = resolve(process.cwd(), 'section889-contacts.yaml');
      const closuresPath = resolve(process.cwd(), 'section889-agency-closures.yaml');
      const reports = emitSection8891bdReports({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        cspUei: (config as any)?.csp_uei ?? undefined,
        cspCageCode: (config as any)?.csp_cage_code ?? undefined,
        contactsPath: existsSync(contactsPath) ? contactsPath : undefined,
        closuresPath: existsSync(closuresPath) ? closuresPath : undefined,
        signingOfficerName: signing?.corporate_signing_officer_name ?? undefined,
        signingOfficerTitle: signing?.corporate_signing_officer_title ?? undefined,
        federalBusinessHoursTz: s889?.reporting?.federal_business_hours_tz ?? undefined,
      });
      console.log(
        `FAR 52.204-25(d) 1BD reporter: ${reports.reports_emitted} report(s) emitted ` +
        `(${reports.reportable_matches} reportable match(es), ${reports.reports_already_present} already present, ` +
        `${reports.deadline_breached_at_emit} past-deadline at emit).`
      );
      ledger.record('section889_1bd_report.emit', {
        status: 'info',
        reports_emitted: reports.reports_emitted,
        reportable_matches: reports.reportable_matches,
        deadline_breached_at_emit: reports.deadline_breached_at_emit,
      });
    } catch (e: any) {
      console.error(`FAR 52.204-25(d) 1BD reporter failed: ${e.message}`);
      log.error({ event: 'section889_1bd_report.fail', err_message: e?.message });
    }
  }

  // ---- FAR 52.204-26 Section 889 Part B annual representation (LOOP-W.W4) —
  // ingest the W.W2 screen result, compute the two FAR 52.204-26(c) "does / does
  // not" answers from the non-suppressed matches, link any W.W3 1BD incidents,
  // sign the canonical-JSON envelope (+ .docx render), and write the LOOP-Q.Q1
  // Marketplace badge feed. Runs AFTER the W.W2 screen + W.W3 reporter (it reads
  // the 1BD ledger for linked incidents) and BEFORE signing so the artifacts are
  // covered by the run manifest. NEVER files the representation in SAM.gov — REO
  // Rule 4. Mandatory operator fields (UEI, officer block, methodology doc) are
  // validated before any write; a missing field throws + this pass logs + skips. ----
  if (args.section889AnnualRep && !args.dryRun) {
    try {
      const s889 = (config as any)?.section_889 ?? {};
      const annual = s889?.annual_representation ?? {};
      const rep = emitSection889AnnualRep({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        offeror: {
          legal_name: s889?.offeror?.legal_name ?? (config as any)?.csp_name ?? undefined,
          unique_entity_id: s889?.offeror?.unique_entity_id ?? (config as any)?.csp_uei ?? undefined,
          cage_code: s889?.offeror?.cage_code ?? (config as any)?.csp_cage_code ?? undefined,
          duns: s889?.offeror?.duns ?? undefined,
          physical_address: s889?.offeror?.physical_address ?? undefined,
        },
        authorizedOfficer: {
          full_name: s889?.authorized_officer?.full_name ?? undefined,
          title: s889?.authorized_officer?.title ?? undefined,
          email: s889?.authorized_officer?.email ?? undefined,
          signing_key_id: s889?.authorized_officer?.signing_key_id ?? undefined,
        },
        reasonableInquiryMethodologyPath: annual?.reasonable_inquiry_methodology_path
          ?? resolve(process.cwd(), 'docs/section889/reasonable-inquiry-methodology.md'),
        includeKasperskyAttachment: annual?.include_kaspersky_attachment !== false,
        validUntilDays: annual?.valid_until_days ?? undefined,
        strictCatalogFreshness: args.strictRisk,
      });
      console.log(
        `FAR 52.204-26 annual representation: provides=${rep.provides_status}, uses=${rep.uses_status} ` +
        `(${rep.linked_incidents_count} linked 1BD incident(s), ${rep.flips.length} flip(s) vs prior, ` +
        `Marketplace badge ${rep.badge_enabled ? 'enabled' : 'grey-listed'}).`
      );
      for (const w of rep.warnings) console.warn(`  ${w}`);
      ledger.record('section889_annual_rep.emit', {
        status: 'info',
        provides_status: rep.provides_status,
        uses_status: rep.uses_status,
        linked_incidents: rep.linked_incidents_count,
        badge_enabled: rep.badge_enabled,
      });
    } catch (e: any) {
      console.error(`FAR 52.204-26 annual representation failed: ${e.message}`);
      log.error({ event: 'section889_annual_rep.fail', err_message: e?.message });
    }
  }

  // ---- Monthly ConMon analysis report (LOOP-E.E1) — aggregate the run's own
  // artifacts (poam.json, KSI-*.json, inventory.json, diff-report.json,
  // scn-classification.json) + CISA KEV + the pinned ConMon Playbook into the
  // human-readable monthly report (json/md/pdf) the agency POC expects attached
  // to the USDA Connect.gov upload. Runs AFTER POA&M / VDR / inventory but
  // BEFORE signing so the report is covered by the run manifest. ----
  if (args.conmonMonthly) {
    try {
      const month = args.conmonMonth ?? new Date().toISOString().slice(0, 7);
      const r = await emitConmonMonthlyReport({
        outDir: args.outDir,
        runId,
        reportMonth: month,
        frmrVersion: config.frmr_version,
        system: {
          name: args.systemName ?? undefined,
          id: args.systemId ?? undefined,
          impactLevel,
          csp: args.cspName ?? undefined,
          fedrampId: args.fedrampPackageId ?? undefined,
        },
        samplingPct: args.samplingPct ?? undefined,
        conmonStrategyHref: args.conmonStrategyHref ?? undefined,
        sspLastReviewed: args.sspLastReviewed ?? undefined,
        authorizationDate: args.authorizationDate ?? undefined,
        playbookPath: existsSync(resolve(PROJECT_ROOT, 'docs/fedramp-conmon-playbook.generated.json'))
          ? resolve(PROJECT_ROOT, 'docs/fedramp-conmon-playbook.generated.json')
          : undefined,
        kevPath: process.env.CLOUD_EVIDENCE_KEV_PATH
          ?? (existsSync(resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json'))
            ? resolve(PROJECT_ROOT, 'docs/cisa-kev.generated.json')
            : undefined),
      });
      const p = r.report.posture;
      console.log(
        `ConMon monthly report (${month}): ${r.jsonPath} + .md + .pdf ` +
          `(KSI pass ${(p.ksi_pass_rate * 100).toFixed(0)}%, ${p.open_poam_count} open POA&M, ` +
          `${p.past_deadline_count} past deadline, ${p.kev_exposure_count} KEV)`,
      );
      ledger.record('conmon_monthly.emit', {
        status: 'info',
        report_month: month,
        open_poam_count: p.open_poam_count,
        past_deadline_count: p.past_deadline_count,
        kev_exposure_count: p.kev_exposure_count,
        warnings: r.report.provenance.warnings?.length ?? 0,
      });
    } catch (e: any) {
      console.error(`ConMon monthly report failed: ${e.message}`);
      log.error({ event: 'conmon_monthly.fail', err_message: e?.message });
    }
  }

  // ---- SSDF per-practice satisfaction matrix (LOOP-T.T2) — join the T.T1 SSDF
  // catalogue to the run's REAL evidence corpus (signed KSI envelopes +
  // risk-scores + subprocessor / supply-chain registers + SBOM + OSCAL POA&M)
  // and emit the per-practice x per-task satisfaction matrix (JSON + .xlsx) per
  // product. Runs AFTER every per-loop emitter (so all evidence exists) and
  // BEFORE signing so the matrix is covered by the run manifest + RFC 3161 TSR.
  // The gate is the OMB M-22-18 procurement signal (--ssdf-attestation). The
  // matrix never auto-signs a producer attestation (REO Rule 1.10) — the CISA
  // Common Form (T.T3) carries the officer signature; T.T2 emits machine
  // evidence only. ----
  if (args.ssdfAttestation && !args.dryRun) {
    try {
      const ssdfCfg = (config as any)?.ssdf ?? {};
      const products: SsdfProductConfig[] = Array.isArray(ssdfCfg.products)
        ? ssdfCfg.products
            .map((p: any) => ({
              id: String(p?.id ?? '').trim(),
              name: String(p?.name ?? p?.id ?? '').trim(),
              ai_enabled: p?.ai_enabled === true,
              critical_software: p?.critical_software === true,
            }))
            .filter((p: SsdfProductConfig) => p.id)
        : [];
      const matrices = emitSsdfSatisfactionMatrix({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        regime: ssdfCfg.regime ?? undefined,
        products: products.length ? products : undefined,
        ksiToProductMap: ssdfCfg.ksi_to_product_map ?? undefined,
      });
      for (const m of matrices) {
        const t = m.totals.tasks_by_status;
        console.log(
          `SSDF satisfaction matrix (${m.product_id}): ${m.json_path} ` +
          `(${m.totals.practices} practices / ${m.totals.tasks} tasks; ` +
          `${t['satisfied']} satisfied, ${t['partially-satisfied']} partial, ${t['not-satisfied']} not-satisfied, ` +
          `${t['requires-operator-input']} need operator input)`
        );
        ledger.record('ssdf_satisfaction_matrix.emit', {
          status: 'info',
          product: m.product_id,
          matrix_id: m.matrix_id,
          tasks_satisfied: t['satisfied'],
          tasks_requires_operator_input: t['requires-operator-input'],
        });
      }
    } catch (e: any) {
      console.error(`SSDF satisfaction matrix failed: ${e.message}`);
      log.error({ event: 'ssdf_satisfaction_matrix.fail', err_message: e?.message });
    }
  }

  // ---- SSDF annual re-attestation cadence + material-change detector (LOOP-T.T4) ----
  // Diffs the T.T2 satisfaction matrix just emitted against the most recent prior
  // snapshot (out/ssdf-attestation-snapshots/<product>/<sha>.json), emits the
  // signed material-change events + per-(product × agency) cadence rows
  // (out/ssdf-material-change-events.json), archives the current matrix as the new
  // baseline, and appends the run to out/ssdf-attestation-ledger.jsonl. Runs AFTER
  // the T.T2 emit (its diff input) + BEFORE T.T3 / signing so the report is covered
  // by the run manifest + RFC 3161 TSR. Gated by the same OMB M-22-18 procurement
  // signal (--ssdf-attestation). Never auto-signs a producer attestation and never
  // files with an agency / CISA RSAA (REO Rule 4) — the tracker capture / RSAA /
  // withdrawal actions are the deferred T.T4 tracker layer (LOOP-T-RISKS T.T4-21..24).
  if (args.ssdfAttestation && !args.dryRun) {
    try {
      const ssdfCfg = (config as any)?.ssdf ?? {};
      const products: SsdfProduct[] = Array.isArray(ssdfCfg.products)
        ? ssdfCfg.products
            .map((p: any): SsdfProduct => ({
              id: String(p?.id ?? '').trim(),
              legal_name: String(p?.legal_name ?? p?.name ?? p?.id ?? '').trim(),
              regime: String(p?.regime ?? '').trim(),
              critical_software: p?.critical_software === true,
              continuous_delivery: p?.continuous_delivery === true,
              major_version_pattern: String(p?.major_version_pattern ?? '').trim(),
              cadence_override_days:
                p?.cadence_override_days === null || p?.cadence_override_days === undefined
                  ? null
                  : Number(p.cadence_override_days),
              poam_extension_allowed: p?.poam_extension_allowed !== false,
              federal_agencies: Array.isArray(p?.federal_agencies)
                ? p.federal_agencies
                    .map((a: any) => ({ id: String(a?.id ?? '').trim(), name: String(a?.name ?? a?.id ?? '').trim() }))
                    .filter((a: { id: string }) => a.id)
                : [],
            }))
            .filter((p: SsdfProduct) => p.id)
        : [];
      const mc = emitSsdfMaterialChanges({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        products,
        configPath: args.configPath,
      });
      console.log(
        `SSDF re-attestation detector: ${mc.json_path} ` +
        `(${mc.products_tracked} product(s), ${mc.status_rows} cadence row(s); ` +
        `${mc.events} material-change event(s), ${mc.events_triggering_reattestation} force re-attestation; ` +
        `${mc.baseline_products} baseline)`,
      );
      ledger.record('ssdf_material_change.emit', {
        status: 'info',
        products_tracked: mc.products_tracked,
        events: mc.events,
        events_triggering_reattestation: mc.events_triggering_reattestation,
        baseline_products: mc.baseline_products,
      });
    } catch (e: any) {
      console.error(`SSDF re-attestation detector failed: ${e.message}`);
      log.error({ event: 'ssdf_material_change.fail', err_message: e?.message });
    }
  }

  // ---- NIST SP 800-218A SSDF-AI extension (LOOP-T.T5) ----
  // Augments the T.T2 satisfaction matrix with the 800-218A AI-model R/C/N items
  // for every in-scope product whose LOOP-O.O5 model card declares an AI use case
  // or dual-use foundation-model status. Runs AFTER the T.T2 matrix emit (its
  // join base) + BEFORE T.T3 / signing so the artefacts are covered by the run
  // manifest + RFC 3161 TSR. Gated by --ssdf-attestation AND
  // config.ssdf.ai_augmentation_enabled AND >=1 in-scope model card; with
  // LOOP-O.O5 unshipped there are no model cards, so the step no-ops
  // (coverage:skipped) — the realizable-core posture as T.T2/T.T3/T.T4. Never
  // fabricates AI evidence (REO Rule 4): an augmentation with no AI-specific
  // evidence inherits its parent task; a new 800-218A AI task with no base parent
  // is requires-operator-input.
  if (args.ssdfAttestation && !args.dryRun) {
    try {
      const ssdfCfg = (config as any)?.ssdf ?? {};
      const aug = emitSsdfAiAugmentation({
        outDir: args.outDir,
        runId,
        cspName: args.cspName ?? (config as any)?.csp_name ?? 'REQUIRES-OPERATOR-INPUT',
        aiAugmentationEnabled: ssdfCfg.ai_augmentation_enabled === true,
        primaryCatalogue: ssdfCfg.primary_catalogue === 'final' ? 'final' : 'IPD',
        productsInScope: Array.isArray(ssdfCfg.ai_products_in_scope) ? ssdfCfg.ai_products_in_scope.map((s: any) => String(s)) : undefined,
        deltaPath: 'docs/sources/ssdf-800-218A-delta.json',
        renderXlsx: renderAiAugmentationXlsx,
      });
      if (aug.skipped) {
        log.info({ event: 'ssdf_ai_augmentation.skipped', reason: aug.reason });
      } else {
        console.log(
          `SSDF 800-218A AI augmentation: ${aug.json_path} ` +
          `(${aug.products_in_scope} in-scope product(s); ${aug.rollup.total_augmentations_evaluated} augmentations — ` +
          `${aug.rollup.satisfied} satisfied, ${aug.rollup.partially_satisfied} partial, ${aug.rollup.requires_operator_input} need operator input)`,
        );
        ledger.record('ssdf_ai_augmentation.emit', {
          status: 'info',
          augmentation_id: aug.augmentation_id,
          products_in_scope: aug.products_in_scope,
          augmentations_evaluated: aug.rollup.total_augmentations_evaluated,
          requires_operator_input: aug.rollup.requires_operator_input,
        });
      }
    } catch (e: any) {
      console.error(`SSDF 800-218A AI augmentation failed: ${e.message}`);
      log.error({ event: 'ssdf_ai_augmentation.fail', err_message: e?.message });
    }
  }

  // ---- CISA Secure Software Development Attestation Common Form (LOOP-T.T3) ----
  // Projects the T.T2 satisfaction matrix (out/ssdf-satisfaction-matrix*.json) +
  // the operator's `ssdf.producer` config into the OMB 1670-0052 Common Form, and
  // emits the unsigned canonical PDF + signed JSON shadow. Runs AFTER the T.T2
  // matrix emit (its evidence backbone) + AFTER the OSCAL POA&M emit (for
  // cannot-comply references) and BEFORE signing so the artifacts are covered by
  // the run manifest + RFC 3161 TSR. The signature/date lines are left blank —
  // the corporate officer signs out of band (T.T4); the system never auto-signs
  // the human attestation (REO Rule 1.10).
  if (args.ssdfCommonForm && !args.dryRun) {
    try {
      const producerCfg = (config as any)?.ssdf?.producer ?? {};
      const cf = emitSsdfCommonForm({
        outDir: args.outDir,
        runId,
        producer: producerCfg,
        configPath: args.configPath,
      });
      const sels = Object.entries(cf.selections).map(([k, v]) => `P${k}:${v}`).join(' ');
      console.log(
        `CISA Common Form (OMB 1670-0052): ${cf.pdf_path} ` +
        `(${cf.fill_rates.length} product(s); ${sels})`,
      );
      ledger.record('ssdf_common_form.emit', {
        status: 'info',
        pdf_sha256: cf.pdf_sha256,
        json_sha256: cf.json_sha256,
        selections: cf.selections,
        ai_profile: cf.ai_profile,
      });
    } catch (e: any) {
      console.error(`CISA Common Form emission failed: ${e.message}`);
      log.error({ event: 'ssdf_common_form.fail', err_message: e?.message });
    }
  }

  // ---- Sign run manifest ----
  if (!args.noSign) {
    try {
      const signRes = signRun({ outDir: args.outDir, runId, frmrVersion: config.frmr_version });
      console.log(`Signed ${signRes.files_signed} evidence file(s) → ${signRes.manifest_path}${signRes.ephemeral_key ? ' (ephemeral key)' : ''}`);
      // Self-verify the manifest we just wrote — catches any disk-write
      // race or symlink shenanigans before downstream consumers see it.
      const v = verifyRun(args.outDir, args.expectedPublicKey ?? undefined);
      if (!v.valid) {
        console.error(`Signature self-verification FAILED: ${v.errors.join('; ')}`);
        log.error({ event: 'sign.self_verify_failed', errors: v.errors });
        process.exitCode = 3;
      }

      // ---- Request RFC 3161 trusted timestamp ----
      // Best-effort: failures here are warnings, not errors. The orchestrator
      // continues — the signed manifest is the baseline; the TSR is an upgrade
      // (it proves WHEN, not just WHO).
      try {
        const tsr = await timestampManifest({ outDir: args.outDir });
        if (tsr.obtained) {
          console.log(`Trusted timestamp obtained from ${tsr.tsa_url} → ${tsr.response_path}`);
        } else {
          console.log(`Trusted timestamp skipped: ${tsr.reason}`);
        }
      } catch (e: any) {
        console.error(`Timestamping failed: ${e.message}`);
        log.error({ event: 'tsa.fail', err_message: e?.message });
      }
    } catch (e: any) {
      console.error(`Signing failed: ${e.message}`);
      log.error({ event: 'sign.fail', err_message: e?.message });
    }
  }

  // ---- Submission package bundler (LOOP-A.A4) ----
  // Runs AFTER signing so the bundle includes the manifest + signature + the
  // RFC 3161 timestamp. Strict mode (--strict-bundle) refuses to write when
  // any required artifact is missing OR the OSCAL chain is broken — the
  // right setting for production submissions to the FedRAMP secure repository.
  if (args.submissionBundle) {
    try {
      const bundle = emitSubmissionBundle({
        outDir: args.outDir,
        runId,
        frmrVersion: config.frmr_version,
        strict: args.strictBundle,
      });
      const chainBadge = bundle.chain_complete ? '✓ chain complete' : '⚠ chain incomplete';
      const gapBadge = bundle.gap_count === 0 ? '✓ no gaps' : `⚠ ${bundle.gap_count} gap(s)`;
      console.log(
        `Submission bundle: ${bundle.bundle_path} ` +
        `(${(bundle.bundle_bytes / 1024).toFixed(1)} KB, ${bundle.artifact_count} artifact(s); ${chainBadge}; ${gapBadge})`,
      );
      console.log(`  Bundle SHA-256: ${bundle.bundle_sha256}`);
      // Bundle emitted; status reflects whether it's submission-ready
      // (no gaps + chain complete). When incomplete, we record 'info' rather
      // than 'fail' because the bundle did write — the operator/CI is left
      // to decide whether to ship it. --strict-bundle is the gate that
      // converts incompleteness into a hard error before write.
      ledger.record('submission_bundle.emit', {
        status: 'info',
        ship_ready: bundle.chain_complete && bundle.gap_count === 0,
        artifact_count: bundle.artifact_count,
        gap_count: bundle.gap_count,
        chain_complete: bundle.chain_complete,
        bundle_sha256: bundle.bundle_sha256,
        bundle_bytes: bundle.bundle_bytes,
      });
    } catch (e: any) {
      console.error(`Submission bundle emission failed: ${e.message}`);
      log.error({ event: 'submission_bundle.fail', err_message: e?.message });
      if (args.strictBundle) process.exitCode = 4;
    }
  }

  // ---- Coverage check ----
  try {
    const cov = checkCoverage(args.outDir, {
      awsAccount,
      gcpProjects: config.gcp.projects,
      regions: config.aws.regions,
      expectedKsis: inScopeKsis.map((k) => k.id),
    });
    if (cov.warnings.length > 0) {
      console.log();
      console.log(`Coverage warnings (${cov.warnings.length}):`);
      for (const w of cov.warnings) console.log(`  ! ${w}`);
      log.warn({
        event: 'coverage.warnings',
        count: cov.warnings.length,
        missing_aws: cov.missing_aws,
        missing_gcp_projects: cov.missing_gcp_projects,
        missing_ksis: cov.missing_ksis,
        ksis_with_zero_findings: cov.ksis_with_zero_findings,
        missing_regions: cov.missing_regions,
      });
    } else {
      console.log(`Coverage: ${cov.actual_aws_accounts.length} AWS account(s), ${cov.actual_gcp_projects.length} GCP project(s), ${cov.actual_ksis.length} KSIs covered.`);
    }
  } catch (e: any) {
    console.error(`Coverage check failed: ${e.message}`);
    log.error({ event: 'coverage.fail', err_message: e?.message });
  }

  // ---- Diff report (always snapshots; report only if requested) ----
  const snapshotPath = resolve(args.outDir, 'previous-run-snapshot.json');
  let diff: any = null;
  if (args.diffReport) {
    try {
      diff = diffReport(args.outDir, snapshotPath, resolve(args.outDir, 'diff-report.json'), resolve(args.outDir, 'diff-report.html'));
      console.log(`Diff: ${diff.regressed_count} regressed, ${diff.fixed_count} fixed, ${diff.new_findings_count} new.`);
    } catch (e: any) { console.error(`Diff report failed: ${e.message}`); }
  }
  // Persist current snapshot for next run regardless
  try { snapshotRun(args.outDir, snapshotPath); } catch (e: any) { console.error(`Snapshot failed: ${e.message}`); }

  // ---- SCN-1: classify the diff as a FedRAMP Significant Change Notification ----
  if (args.scn) {
    try {
      const scn = buildScnReport({
        outDir: args.outDir, runId,
        proposedChangesPath: args.scnProposedPath ?? undefined,
        systemName: args.systemName ?? undefined,
        cspName: args.oscalOrgName ?? undefined,
      });
      writeScnReport(scn, resolve(args.outDir, 'scn-classification.json'), resolve(args.outDir, 'scn-notice-draft.md'));
      console.log(`SCN: ${scn.totals.significant} significant, ${scn.totals.advisory} advisory, ${scn.totals.not_significant} not-significant (of ${scn.totals.total} change(s)) → scn-classification.json + scn-notice-draft.md`);
      ledger.record('scn.classify', { status: 'info', ...scn.totals });
    } catch (e: any) {
      console.error(`SCN classification failed: ${e?.message ?? e}`);
      log.error({ event: 'scn.fail', err_message: e?.message });
    }
  }

  // ---- HTML report ----
  if (args.htmlReport) {
    try {
      const { path: p, ksis } = generateHtmlReport(args.outDir, resolve(args.outDir, 'report.html'));
      console.log(`HTML report: ${p} (${ksis} KSIs)`);
    } catch (e: any) { console.error(`HTML report failed: ${e.message}`); }
  }

  // ---- CSV export ----
  if (args.csvExport) {
    try {
      const { path: p, rows } = exportFindingsCsv(args.outDir, resolve(args.outDir, 'findings.csv'));
      console.log(`CSV: ${p} (${rows} finding rows)`);
    } catch (e: any) { console.error(`CSV export failed: ${e.message}`); }
  }

  // ---- Drift notification ----
  if (args.notifyOnDrift && diff) {
    try {
      const driftEvents = diff.ksi_diffs.flatMap((k: any) =>
        k.previous_pass !== undefined && k.current_pass !== undefined && k.previous_pass !== k.current_pass
          ? [{ ksi_id: k.ksi_id, previous_pass: k.previous_pass, current_pass: k.current_pass }]
          : [],
      );
      const result = await notifyDrift({
        run_id: runId,
        drift_events: driftEvents,
        total_ksis: summary.rollup.total_ksis,
        failed_ksis: summary.rollup.failed,
        evidence_url_base: process.env.EVIDENCE_URL_BASE,
      });
      console.log(`Notify: Slack=${result.slack}, PagerDuty=${result.pagerduty}${result.errors ? ` (errors: ${result.errors.join('; ')})` : ''}`);
    } catch (e: any) { console.error(`Notify failed: ${e.message}`); }
  }

  // ---- Paramify push ----
  if (args.pushParamify) {
    const token = process.env.PARAMIFY_API_TOKEN;
    if (!token) {
      console.error('--push-paramify requires PARAMIFY_API_TOKEN env var.');
    } else {
      try {
        const r = await pushAllToParamify(args.outDir, { apiToken: token, evidenceUrlBase: process.env.EVIDENCE_URL_BASE });
        const sent = r.filter((x) => x.status === 'sent').length;
        const err = r.filter((x) => x.status === 'error').length;
        console.log(`Paramify: ${sent} sent, ${err} errors`);
      } catch (e: any) { console.error(`Paramify push failed: ${e.message}`); }
    }
  }

  // ---- Tracker push ----
  if (args.pushTracker) {
    const token = process.env.TRACKER_API_TOKEN;
    if (!token) {
      console.error('--push-tracker requires TRACKER_API_TOKEN env var.');
    } else {
      try {
        const cfg = { apiToken: token, baseUrl: process.env.TRACKER_BASE_URL, evidenceUrlBase: process.env.EVIDENCE_URL_BASE };
        const r = await pushAllToTracker(args.outDir, cfg);
        const sent = r.filter((x) => x.status === 'sent').length;
        const err = r.filter((x) => x.status === 'error').length;
        const unsup = r.filter((x) => x.status === 'unsupported_ksi').length;
        console.log(`Tracker: ${sent} sent, ${err} errors, ${unsup} unsupported KSI IDs`);

        const driftEvents = diff?.ksi_diffs?.filter((k: any) => k.previous_pass !== undefined && k.previous_pass !== k.current_pass)?.length ?? 0;
        const negDrift = diff?.regressed_count ?? 0;
        const tel = await pushRunTelemetry(args.outDir, cfg, {
          run_id: runId,
          started_at: startedAt,
          finished_at: finishedAt,
          frmr_version: config.frmr_version,
          total_ksis: summary.rollup.total_ksis,
          passed_ksis: summary.rollup.passed,
          failed_ksis: summary.rollup.failed,
          drift_events: driftEvents,
          negative_drift: negDrift,
          summary,
        });
        console.log(`Tracker run telemetry: ${tel.status}${tel.error ? ` (${tel.error})` : ''}`);
      } catch (e: any) { console.error(`Tracker push failed: ${e.message}`); }
    }
  }

  // ---- Phase F integrations (LLM, tickets, SIEM, webhook) ----
  // Helper: iterate evidence files. The integrations need the full evidence
  // file (not just summary stats), so we re-read each KSI file from disk.
  const loadEvidenceFiles = (): EvidenceFile[] => {
    const out: EvidenceFile[] = [];
    for (const f of inScopeKsis) {
      const p = resolve(args.outDir, `${f.id}.json`);
      if (!existsSync(p)) continue;
      try { out.push(JSON.parse(readFileSync(p, 'utf8'))); } catch { /* skip */ }
    }
    return out;
  };

  // ---- LLM PR generator ----
  if (args.llmGeneratePrs) {
    if (!process.env.ANTHROPIC_API_KEY) {
      console.error('--llm-generate-prs requires ANTHROPIC_API_KEY env var.');
    } else {
      const evidenceFiles = loadEvidenceFiles();
      const prResults: Array<{ ksi: string; rule: string; pr_title?: string; reason?: string }> = [];
      try {
        for (const ev of evidenceFiles) {
          const r = await generatePrsForEvidence(ev);
          for (const item of r) {
            if (item.result.skipped) {
              prResults.push({ ksi: ev.ksi_id, rule: item.rule, reason: item.result.reason });
            } else if (item.result.pr) {
              prResults.push({ ksi: ev.ksi_id, rule: item.rule, pr_title: item.result.pr.title });
            }
          }
        }
        const prOutPath = resolve(args.outDir, 'llm-prs.json');
        writeFileSync(prOutPath, JSON.stringify(prResults, null, 2));
        const okN = prResults.filter((r) => r.pr_title).length;
        const skipN = prResults.filter((r) => r.reason).length;
        console.log(`LLM PR generator: ${okN} draft(s), ${skipN} skipped → ${prOutPath}`);
      } catch (e: any) {
        console.error(`LLM PR generation failed: ${e.message}`);
        log.error({ event: 'llm.fail', err_message: e?.message });
      }
    }
  }

  // ---- Ticket push ----
  if (args.ticketProvider) {
    let driver;
    try {
      if (args.ticketProvider === 'github') {
        const token = process.env.GITHUB_TOKEN;
        const repo = process.env.GITHUB_REPO; // "owner/repo"
        if (!token || !repo) throw new Error('GITHUB_TOKEN + GITHUB_REPO env vars required for --ticket-push github');
        driver = gitHubIssuesDriver({ token, repo, labels: ['fedramp-20x'] });
      } else if (args.ticketProvider === 'jira') {
        const siteUrl = process.env.JIRA_SITE_URL;
        const email = process.env.JIRA_EMAIL;
        const apiToken = process.env.JIRA_API_TOKEN;
        const projectKey = process.env.JIRA_PROJECT_KEY;
        if (!siteUrl || !email || !apiToken || !projectKey) {
          throw new Error('JIRA_SITE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY required');
        }
        driver = jiraDriver({ siteUrl, email, apiToken, projectKey });
      } else {
        const instanceUrl = process.env.SERVICENOW_URL;
        const user = process.env.SERVICENOW_USER;
        const password = process.env.SERVICENOW_PASSWORD;
        if (!instanceUrl || !user || !password) {
          throw new Error('SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD required');
        }
        driver = serviceNowDriver({ instanceUrl, user, password });
      }
      let opened = 0, updated = 0, reopened = 0, failed = 0;
      for (const ev of loadEvidenceFiles()) {
        const r = await pushTickets(driver, ev);
        for (const t of r.pushed) {
          if (t.status === 'opened') opened++;
          else if (t.status === 'updated') updated++;
          else if (t.status === 'reopened') reopened++;
          else if (t.status === 'failed') failed++;
        }
      }
      console.log(`Tickets (${args.ticketProvider}): ${opened} opened, ${updated} updated, ${reopened} reopened, ${failed} failed`);
    } catch (e: any) {
      console.error(`Ticket push failed: ${e.message}`);
      log.error({ event: 'ticket.fail', provider: args.ticketProvider, err_message: e?.message });
    }
  }

  // ---- SIEM push (OCSF) ----
  if (args.siemUrl) {
    try {
      const authHeader = process.env.CLOUD_EVIDENCE_SIEM_AUTH; // e.g. "Splunk <token>" or "Bearer <token>"
      const format = (process.env.CLOUD_EVIDENCE_SIEM_FORMAT as 'ocsf-jsonl' | 'splunk-hec' | 'ocsf-array') ?? 'ocsf-jsonl';
      let totalSent = 0, totalFailed = 0;
      for (const ev of loadEvidenceFiles()) {
        const r = await pushEvidenceToSiem(ev, { url: args.siemUrl, authHeader, format });
        totalSent += r.events_sent;
        totalFailed += r.failures.length;
      }
      console.log(`SIEM: ${totalSent} event(s) sent, ${totalFailed} batch failure(s)`);
    } catch (e: any) {
      console.error(`SIEM push failed: ${e.message}`);
      log.error({ event: 'siem.fail', err_message: e?.message });
    }
  }

  // ---- Generic webhook ----
  if (args.webhookUrl) {
    const secret = process.env.CLOUD_EVIDENCE_WEBHOOK_SECRET;
    if (!secret) {
      console.error('--webhook-url requires CLOUD_EVIDENCE_WEBHOOK_SECRET env var.');
    } else {
      try {
        // Run-summary always; per-finding only if WEBHOOK_PER_FINDING=1
        const sumRes = await sendRunSummary({ url: args.webhookUrl, secret }, summary);
        let perFindingN = 0, perFindingFail = 0;
        if (process.env.CLOUD_EVIDENCE_WEBHOOK_PER_FINDING === '1') {
          for (const ev of loadEvidenceFiles()) {
            const results = await sendFindingWebhooks({ url: args.webhookUrl, secret }, ev);
            perFindingN += results.filter((r) => r.ok).length;
            perFindingFail += results.filter((r) => !r.ok).length;
          }
        }
        console.log(`Webhook: run-summary ${sumRes.ok ? '✓' : '✗'}` + (perFindingN > 0 || perFindingFail > 0 ? `, per-finding ${perFindingN} sent / ${perFindingFail} failed` : ''));
      } catch (e: any) {
        console.error(`Webhook push failed: ${e.message}`);
        log.error({ event: 'webhook.fail', err_message: e?.message });
      }
    }
  }

  // Exit-code policy (separate from process.exit() in early failure paths above):
  //   0 — clean run; failing findings are DATA, not an error.
  //   2 — schema validation failed under --strict-schema (set earlier).
  //   3 — signing self-verify failed (set earlier).
  //   4 — at least one collector threw an exception (vs. simply emitting failing findings).
  //       This is what CI runners should fail on — the script itself broke, not just compliance.
  const collectorExceptions = results.filter((r) =>
    // Heuristic: empty providers + a "collector error" warning means the catch in runOneKsi fired.
    // (Normal KSIs always populate at least one provider block.)
    r.findings_count === 0 && r.warnings_count > 0,
  );
  if (collectorExceptions.length > 0 && process.exitCode === undefined) {
    log.warn({
      event: 'run.collector_exceptions',
      count: collectorExceptions.length,
      ksi_ids: collectorExceptions.map((r) => r.ksi_id),
    });
    console.error(`\n${collectorExceptions.length} collector(s) threw exceptions: ${collectorExceptions.map((r) => r.ksi_id).join(', ')}`);
    console.error('CI runners: this is exit code 4. Collectors are broken — not just compliance gaps.');
    process.exitCode = 4;
  }
}

// Only auto-run when invoked as the entry script (tsx core/orchestrator.ts ...).
// When imported by a test, this guard suppresses the auto-run so the test can
// craft argv + env then invoke main() itself.
const isEntryScript = (() => {
  try {
    return import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
  } catch {
    return false;
  }
})();
if (isEntryScript) {
  main().catch((e) => {
    console.error('Fatal error:', e);
    process.exit(1);
  });
}

function buildSummaryForLlm(ksi: KsiEntry, providers: ProviderBlock[], rollup: ReturnType<typeof makeRollup>): string {
  const parts: string[] = [];
  parts.push(`KSI ${ksi.id} (${ksi.scope}): ${ksi.name}.`);
  parts.push(`FRMR statement: "${ksi.statement}"`);
  if (ksi.nist_controls?.length) {
    parts.push(`Maps to NIST 800-53 controls: ${ksi.nist_controls.join(', ')}.`);
  }
  if (rollup.pass) {
    parts.push(`All ${rollup.passing_findings} finding(s) passed across ${providers.length} provider block(s).`);
  } else {
    parts.push(`${rollup.failing_findings} of ${rollup.passing_findings + rollup.failing_findings} finding(s) failed.`);
    const failingRules = providers.flatMap((p) => p.findings.filter((f) => !f.passed).map((f) => `${p.provider}:${f.rule}(${f.severity})`));
    if (failingRules.length) parts.push(`Failing rules: ${failingRules.join('; ')}.`);
  }
  if (rollup.alternatives_in_play > 0) {
    parts.push(`${rollup.alternatives_in_play} alternative satisfier(s) detected — review evidence_required.`);
  }
  const tools = providers.flatMap((p) => p.third_party_tools_detected ?? []);
  if (tools.length) {
    parts.push(`3rd-party tools detected: ${[...new Set(tools.map((t) => t.name))].join(', ')}.`);
  }
  return parts.join(' ');
}
