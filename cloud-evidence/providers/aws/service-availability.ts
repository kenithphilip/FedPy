/**
 * Service-availability probes.
 *
 * Read-only, cheap "is this service usable here?" checks for the detective /
 * data services whose absence leaves report columns blank. Instead of a silent
 * blank + a warning buried in the log, we emit a structured status per service so
 * the report can say WHY a lens is empty:
 *
 *   ENABLED        — reachable and turned on (data will populate)
 *   DISABLED       — reachable but not enabled in this account (enable to populate)
 *   NOT_AVAILABLE  — no endpoint in this partition/region (e.g. Macie/CE in GovCloud)
 *   ACCESS_DENIED  — IAM/SCP denies the read
 *   UNKNOWN        — an unexpected error
 *
 * Each probe is a single lightweight read; failures are classified, never thrown.
 */
import { classifyError } from '../../core/error-diagnostics.ts';
import * as aws from '../../core/auth/aws.ts';
import { BatchGetAccountStatusCommand } from '@aws-sdk/client-inspector2';
import { ListDetectorsCommand } from '@aws-sdk/client-guardduty';
import { GetFindingsCommand } from '@aws-sdk/client-securityhub';
import { GetMacieSessionCommand } from '@aws-sdk/client-macie2';
import { GetCostAndUsageCommand } from '@aws-sdk/client-cost-explorer';
import { DescribeConfigurationRecorderStatusCommand } from '@aws-sdk/client-config-service';
import { ListAnalyzersCommand } from '@aws-sdk/client-accessanalyzer';

export type ServiceStatus = 'ENABLED' | 'DISABLED' | 'NOT_AVAILABLE' | 'ACCESS_DENIED' | 'UNKNOWN';

export interface ServiceAvailability {
  service: string;
  status: ServiceStatus;
  /** What the report loses when this isn't ENABLED. */
  impact: string;
  /** Human detail (error class / note). */
  detail: string;
}

/** Map a caught error to a service status (network/ENOTFOUND ⇒ NOT_AVAILABLE). */
function statusFromError(err: unknown): { status: ServiceStatus; detail: string } {
  const klass = classifyError(err);
  const msg = (err as { message?: string })?.message ?? '';
  switch (klass) {
    case 'network': return { status: 'NOT_AVAILABLE', detail: 'No service endpoint in this partition/region.' };
    case 'access_denied': return { status: 'ACCESS_DENIED', detail: 'IAM or SCP denies the read.' };
    case 'not_enabled': return { status: 'DISABLED', detail: 'Service not enabled in this account/region.' };
    case 'not_found': return { status: 'DISABLED', detail: 'No resource/session — service not enabled.' };
    default: return { status: 'UNKNOWN', detail: msg.slice(0, 160) };
  }
}

/**
 * Probe the key detective/data services. Returns one status row each. Read-only:
 * every call is a Describe/List/Get with a tiny result set.
 */
export async function probeServiceAvailability(auth: aws.AwsAuth): Promise<ServiceAvailability[]> {
  const out: ServiceAvailability[] = [];

  // AWS Config recorder — the discovery backbone.
  try {
    const cfg = aws.configService(auth);
    const r = await cfg.send(new DescribeConfigurationRecorderStatusCommand({}));
    const recording = (r.ConfigurationRecordersStatus ?? []).some((s) => s.recording);
    out.push({ service: 'AWS Config', status: recording ? 'ENABLED' : 'DISABLED',
      impact: 'All-resource-type discovery breadth.', detail: recording ? 'Recorder is recording.' : 'Recorder present but not recording.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'AWS Config', status: s.status, impact: 'All-resource-type discovery breadth.', detail: s.detail }); }

  // Amazon Inspector v2 — vulnerability scanning.
  try {
    const insp = aws.inspector2(auth);
    const r = await insp.send(new BatchGetAccountStatusCommand({}));
    const acct = (r.accounts ?? [])[0];
    const res = acct?.resourceState;
    const on = acct?.state?.status === 'ENABLED' || res?.ec2?.status === 'ENABLED' || res?.ecr?.status === 'ENABLED' || res?.lambda?.status === 'ENABLED';
    out.push({ service: 'Amazon Inspector v2', status: on ? 'ENABLED' : 'DISABLED',
      impact: 'Vuln Scan / In-Latest-Scan columns + CNAPP remediation lever.', detail: on ? 'Scanning active.' : 'Account status DISABLED — enable to populate.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'Amazon Inspector v2', status: s.status, impact: 'Vuln Scan / In-Latest-Scan columns + CNAPP lever.', detail: s.detail }); }

  // GuardDuty — threat detection.
  try {
    const gd = aws.guardduty(auth);
    const r = await gd.send(new ListDetectorsCommand({}));
    const on = (r.DetectorIds ?? []).length > 0;
    out.push({ service: 'Amazon GuardDuty', status: on ? 'ENABLED' : 'DISABLED',
      impact: 'Threat findings + Threat-Detection lever.', detail: on ? `${r.DetectorIds!.length} detector(s).` : 'No detector — enable to populate.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'Amazon GuardDuty', status: s.status, impact: 'Threat findings + Threat-Detection lever.', detail: s.detail }); }

  // Security Hub — posture aggregation.
  try {
    const sh = aws.securityhub(auth);
    await sh.send(new GetFindingsCommand({ MaxResults: 1 }));
    out.push({ service: 'AWS Security Hub', status: 'ENABLED', impact: 'Posture rollup + critical-finding gates.', detail: 'Findings API reachable.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'AWS Security Hub', status: s.status, impact: 'Posture rollup + critical-finding gates.', detail: s.detail }); }

  // Macie — S3 data classification.
  try {
    const m = aws.macie(auth);
    await m.send(new GetMacieSessionCommand({}));
    out.push({ service: 'Amazon Macie', status: 'ENABLED', impact: 'Data Classification column.', detail: 'Session active.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'Amazon Macie', status: s.status, impact: 'Data Classification column (else tag-supplied).', detail: s.detail }); }

  // Cost Explorer — cost estimates.
  try {
    const ce = aws.costExplorer(auth);
    await ce.send(new GetCostAndUsageCommand({ TimePeriod: { Start: '2020-01-01', End: '2020-01-02' }, Granularity: 'DAILY', Metrics: ['UnblendedCost'] }));
    out.push({ service: 'AWS Cost Explorer', status: 'ENABLED', impact: 'Monthly Cost Est column.', detail: 'Reachable.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'AWS Cost Explorer', status: s.status, impact: 'Monthly Cost Est column.', detail: s.detail }); }

  // IAM Access Analyzer — external-access findings.
  try {
    const aa = aws.accessanalyzer(auth);
    const r = await aa.send(new ListAnalyzersCommand({ type: 'ACCOUNT' }));
    const on = (r.analyzers ?? []).length > 0;
    out.push({ service: 'IAM Access Analyzer', status: on ? 'ENABLED' : 'DISABLED',
      impact: 'External-access findings (IAM lens).', detail: on ? `${r.analyzers!.length} analyzer(s).` : 'No analyzer configured.' });
  } catch (e) { const s = statusFromError(e); out.push({ service: 'IAM Access Analyzer', status: s.status, impact: 'External-access findings (IAM lens).', detail: s.detail }); }

  return out;
}
