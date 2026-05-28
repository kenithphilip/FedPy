/**
 * AWS VDR (Vulnerability Detection & Response) live-scan collector.
 *
 * Pulls current vulnerability findings (READ-ONLY) from Amazon Inspector v2 —
 * which covers both EC2/Lambda package vulnerabilities and ECR enhanced image
 * scanning — normalizes them into the VDR ledger (core/vdr-ledger.ts), joins the
 * CISA KEV catalog (core/kev-feed.ts), and reports SLA breaches via the
 * VDR-TFR-* timeframe tables. Emits two findings: (1) detection capability is
 * enabled, (2) no SLA breaches outstanding.
 *
 * STRICTLY READ-ONLY: List/BatchGet only. Wrapped with diagnoseAwsError so an
 * AccessDenied names the exact IAM action. Degrades gracefully when Inspector is
 * not enabled (warning, not a crash).
 *
 * Registered as KSI-AFR-VDR (the AFR pointer to the VDR process); the detailed
 * VDR-* FRR requirements are additionally tracked via process attestation.
 */
import { ListFindingsCommand, BatchGetAccountStatusCommand } from '@aws-sdk/client-inspector2';

import * as aws from '../../core/auth/aws.ts';
import type { ProviderBlock, RawEvidence, AffectedResource, Finding, KeyWord } from '../../core/envelope.ts';
import { finding, severityForKeyWord } from '../../core/findings.ts';
import type { CollectorContext } from '../../core/ksi-map.ts';
import { classifyError, diagnoseAwsError } from '../../core/error-diagnostics.ts';
import { loadKevCatalog } from '../../core/kev-feed.ts';
import { buildLedger, type LedgerEntry, type Severity, type ImpactTier } from '../../core/vdr-ledger.ts';
import { summarizeVdr, type VdrSummary } from '../../core/vdr-report.ts';

const MAX_PAGINATION_ITERATIONS = 1000;

function ev(source: string, data: unknown): RawEvidence { return { source, captured_at: new Date().toISOString(), data: data === undefined ? null : data }; }

/** Map an Inspector severity to the ledger severity scale. */
export function normalizeSeverity(s: unknown): Severity {
  switch (String(s ?? '').toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

/** Read the run impact tier from the environment (set by the orchestrator). */
export function impactLevelFromEnv(): ImpactTier {
  const v = String(process.env.CLOUD_EVIDENCE_IMPACT_LEVEL ?? 'moderate').toLowerCase();
  return v === 'low' || v === 'high' ? (v as ImpactTier) : 'moderate';
}

function toIso(v: unknown): string {
  if (v instanceof Date) return v.toISOString();
  const d = new Date(String(v ?? ''));
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

/**
 * Pure converter: Inspector2 finding objects → ledger entries. Exported for tests.
 */
export function toLedgerEntries(rawFindings: any[]): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  for (const f of rawFindings ?? []) {
    if (!f || typeof f !== 'object') continue;
    const cve = f.packageVulnerabilityDetails?.vulnerabilityId
      ?? (Array.isArray(f.packageVulnerabilityDetails?.relatedVulnerabilities) ? f.packageVulnerabilityDetails.relatedVulnerabilities[0] : undefined);
    const resource = Array.isArray(f.resources) ? f.resources[0]?.id : undefined;
    const epssRaw = f.epss?.score;
    out.push({
      cve: typeof cve === 'string' ? cve : undefined,
      severity: normalizeSeverity(f.severity),
      first_seen: toIso(f.firstObservedAt ?? f.updatedAt),
      source: 'inspector2',
      resource: typeof resource === 'string' ? resource : undefined,
      kev: false, // buildLedger enriches against the KEV catalog
      epss: typeof epssRaw === 'number' ? epssRaw : undefined,
      state: String(f.status ?? '').toUpperCase() === 'SUPPRESSED' ? 'accepted'
        : String(f.status ?? '').toUpperCase() === 'CLOSED' ? 'remediated' : 'detected',
    });
  }
  return out;
}

export async function collectVdrScan(c: CollectorContext): Promise<ProviderBlock> {
  const region = c.aws?.region ?? 'us-east-1';
  const auth = c.aws?.auth ?? aws.makeAwsAuth(region);
  let account = c.aws?.account_id ?? null;
  if (!account) { try { account = (await aws.whoAmI(auth)).account; } catch { /* */ } }
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const kw: KeyWord = 'MUST';
  const tier = impactLevelFromEnv();

  // 1. Detection capability — is Inspector v2 enabled for this account?
  let inspectorEnabled = false;
  try {
    const insp = aws.inspector2(auth);
    try {
      const status = await insp.send(new BatchGetAccountStatusCommand({}));
      const acct = (status.accounts ?? [])[0];
      const res = acct?.resourceState;
      inspectorEnabled = acct?.state?.status === 'ENABLED'
        || res?.ec2?.status === 'ENABLED' || res?.ecr?.status === 'ENABLED' || res?.lambda?.status === 'ENABLED';
      evidence.push(ev('inspector2.BatchGetAccountStatus', { account_status: acct?.state?.status, resource_state: res }));
    } catch (e) {
      const klass = classifyError(e);
      if (klass !== 'not_enabled' && klass !== 'not_found') warnings.push(diagnoseAwsError(e, 'inspector2.BatchGetAccountStatus', 'inspector2:BatchGetAccountStatus'));
    }

    // 2. Pull active package-vulnerability findings.
    const raw: any[] = [];
    if (inspectorEnabled) {
      let tok: string | undefined; let iter = 0;
      do {
        const r = await insp.send(new ListFindingsCommand({
          nextToken: tok,
          maxResults: 100,
          filterCriteria: { findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }] },
        }));
        for (const f of r.findings ?? []) raw.push(f);
        const next = r.nextToken;
        tok = next && next !== tok ? next : undefined;
      } while (tok && ++iter < MAX_PAGINATION_ITERATIONS);
      evidence.push(ev('inspector2.ListFindings', { count: raw.length }));
    }

    // 3. Ledger + KEV + SLA.
    const kev = await loadKevCatalog();
    if (kev.warnings.length) warnings.push(...kev.warnings.map((w) => `KEV: ${w}`));
    const ledger = buildLedger(toLedgerEntries(raw), kev, { tier });
    const summary = summarizeVdr(ledger);
    evidence.push(ev('vdr.summary', summary));

    const findings = buildVdrFindings(inspectorEnabled, summary, kev.source, kw, account);
    return { provider: 'aws', account_id: account, region_set: [region], evidence, findings, warnings };
  } catch (e) {
    warnings.push(diagnoseAwsError(e, 'inspector2', 'inspector2:ListFindings + inspector2:BatchGetAccountStatus'));
    // Still emit a (failing) capability finding so the requirement is represented.
    const findings = buildVdrFindings(false, summarizeVdr([]), 'none', kw, account);
    return { provider: 'aws', account_id: account, region_set: [region], evidence, findings, warnings };
  }
}

/** Build the two VDR findings (shared shape; exported for the GCP collector + tests). */
export function buildVdrFindings(
  detectionEnabled: boolean,
  summary: VdrSummary,
  kevSource: string,
  kw: KeyWord,
  scopeId: string | null,
  provider: 'aws' | 'gcp' = 'aws',
): Finding[] {
  const scannerName = provider === 'gcp' ? 'GCP Container/Artifact Analysis' : 'Amazon Inspector v2';
  const scannerResourceType = provider === 'gcp' ? 'gcp_container_analysis' : 'aws_inspector2';
  const altSatisfiers = [
    { via: 'Wiz / Prisma Cloud / Orca / Tenable / Snyk / Qualys', description: 'A dedicated vulnerability/CNAPP scanner provides equivalent (often deeper) detection across the estate.', evidence_required: ['Scanner coverage report', 'Sample finding with SLA tracking'], detected: false, detection_signals: [] },
    { via: 'HackerOne / Bugcrowd (vulnerability disclosure / bug bounty)', description: 'A VDP/bug-bounty program is an additional detection channel required by VDR.', evidence_required: ['Program URL + scope', 'Sample triaged report'], detected: false, detection_signals: [] },
  ];
  const detection = finding({
    rule: `${provider}.vdr.detection_capability_enabled`,
    passed: detectionEnabled,
    severity: severityForKeyWord(kw),
    applicable_key_word: kw,
    current: {
      summary: detectionEnabled
        ? `${scannerName} is enabled — continuous vulnerability detection is active.`
        : `${scannerName} is NOT enabled/reachable — no native continuous vulnerability detection.`,
      observations: { detection_enabled: detectionEnabled, kev_source: kevSource, total_findings: summary.total },
    },
    target: { summary: 'A vulnerability-detection capability continuously scans all in-scope resources.', rationale: 'KSI/VDR / NIST RA-5, SI-2, SI-3, SI-5. Vulnerability detection must be systematic and persistent.' },
    gap: detectionEnabled ? undefined : {
      description: 'Without an enabled scanner, upstream vulnerabilities go undetected.',
      affected_resources: [{ type: scannerResourceType, identifier: scopeId ?? 'account', name: scannerName }],
    },
    remediation: detectionEnabled ? undefined : {
      summary: `Enable ${scannerName} (or wire a 3rd-party scanner) across all in-scope resources.`,
      options: [{
        approach: `Enable ${scannerName} for the account/project.`, mechanism: 'terraform', owner_team: 'Security',
        cost_impact: { level: 'low', notes: 'Per-resource scan pricing.' }, availability_impact: { level: 'none', notes: 'Scanning only.' },
        customer_visible: { level: 'none', notes: 'Internal.' }, effort_estimate: { magnitude: 'hours', notes: 'Enable + verify coverage.' },
        steps: [`Enable ${scannerName}.`, 'Confirm coverage across compute + container images.', 'Route findings to your ticketing/SLA workflow.'],
      }],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ra-5', 'ra-5.2', 'si-2', 'si-3', 'si-5'],
  });

  const noBreaches = finding({
    rule: `${provider}.vdr.no_sla_breaches`,
    passed: summary.overdue === 0,
    severity: summary.overdue === 0 ? severityForKeyWord(kw) : 'high',
    applicable_key_word: kw,
    current: {
      summary: summary.overdue === 0
        ? `No vulnerability SLA breaches (${summary.total} finding(s); ${summary.kev_count} KEV; oldest open ${summary.oldest_open_days}d).`
        : `${summary.overdue} vulnerability(ies) are past their remediation SLA (${summary.kev_count} KEV in scope).`,
      observations: summary,
    },
    target: { summary: 'All vulnerabilities are remediated within the FedRAMP VDR timeframes (KEV / PVR / MAV).', rationale: 'KSI/VDR / NIST RA-5, SI-2. Detected vulnerabilities must be remediated promptly within defined timeframes.' },
    gap: summary.overdue === 0 ? undefined : {
      description: 'Vulnerabilities past their SLA represent unmitigated, possibly exploited, risk.',
      affected_resources: summary.sla_breaches.slice(0, 50).map<AffectedResource>((b) => ({
        type: 'vulnerability', identifier: b.cve ?? b.resource ?? 'unknown', name: b.cve ?? 'finding',
        attributes: { severity: b.severity, kev: b.kev, due: b.sla?.due, basis: b.sla?.basis },
      })),
    },
    remediation: summary.overdue === 0 ? undefined : {
      summary: 'Remediate or formally accept each overdue vulnerability; prioritize KEV + internet-reachable.',
      options: [{
        approach: 'Patch/redeploy affected resources; for KEV entries treat the CISA due date as hard.', mechanism: 'process', owner_team: 'Security',
        cost_impact: { level: 'low', notes: 'Engineering effort.' }, availability_impact: { level: 'medium', notes: 'Patching may need maintenance windows.' },
        customer_visible: { level: 'none', notes: 'Internal.' }, effort_estimate: { magnitude: 'days', notes: 'Depends on backlog.' },
        steps: ['Sort breaches by KEV + internet-reachable + severity.', 'Patch/redeploy or apply compensating controls.', 'Record formal risk acceptance for any that cannot be met in time.'],
      }],
    },
    alternative_satisfiers: altSatisfiers,
    nist_controls: ['ra-5', 'si-2', 'si-5'],
  });

  return [detection, noBreaches];
}
