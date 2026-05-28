/**
 * SIEM push using the OCSF (Open Cybersecurity Schema Framework) schema.
 *
 * OCSF v1.2 defines a `compliance_finding` class (class_uid = 2003) suitable
 * for compliance evidence. Splunk, Sumo Logic, Chronicle, Snowflake, Datadog,
 * and most modern SIEMs ingest OCSF natively or via a connector. By emitting
 * OCSF directly we avoid having one bespoke integration per SIEM vendor.
 *
 * Endpoint:
 *   - Configurable URL (Splunk HEC, Datadog logs intake, generic HTTP).
 *   - Auth: Bearer token / Splunk-style "Authorization: Splunk <token>" / etc.
 *
 * Batching:
 *   - We send findings in batches of N (default 100) to amortize HTTPS overhead
 *     and stay under most SIEMs' single-payload limits.
 *
 * Error handling:
 *   - Each batch is retried up to 3 times with backoff via core/retry.ts.
 *   - Per-batch failures are recorded; the function returns a result so the
 *     orchestrator can surface a count, but does NOT throw.
 *
 * OCSF references:
 *   - https://schema.ocsf.io/ — official schema browser.
 *   - https://schema.ocsf.io/2003 — compliance_finding class definition.
 */
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { Finding, EvidenceFile } from './envelope.ts';
import { withRetry } from './retry.ts';
import { log } from './log.ts';

const OCSF_VERSION = '1.2.0';
const OCSF_COMPLIANCE_FINDING_CLASS_UID = 2003;

interface OcsfComplianceFinding {
  // Required metadata
  metadata: {
    version: string;
    product: { name: string; vendor_name?: string; version?: string; lang?: string };
    profiles?: string[];
  };
  category_uid: 2;            // Findings
  category_name: 'Findings';
  class_uid: 2003;            // compliance_finding
  class_name: 'Compliance Finding';
  type_uid: 200301 | 200302;  // 200301 = Create, 200302 = Update
  type_name: 'Compliance Finding: Create' | 'Compliance Finding: Update';
  severity_id: 1 | 2 | 3 | 4 | 5; // 1=Informational … 5=Critical
  severity: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  status_id: 1 | 2;            // 1=New, 2=In Progress
  status: 'New' | 'In Progress';
  activity_id: 1 | 2;          // 1=Create, 2=Update
  activity_name: 'Create' | 'Update';
  // Event time
  time: number;                // epoch milliseconds
  // Compliance-finding-specific
  compliance: {
    requirements: string[];    // e.g. ["IA-2(1)", "IA-2(2)"]
    standards: string[];       // e.g. ["FedRAMP 20x Moderate"]
    control: string;           // KSI-IAM-MFA
    status: 'Pass' | 'Fail' | 'Warning';
    status_detail?: string;
  };
  finding_info: {
    title: string;
    desc: string;
    uid: string;               // stable identifier
    types?: string[];
  };
  // Resource the finding is about
  resources?: Array<{ uid?: string; name?: string; type?: string; cloud_partition?: string; region?: string }>;
  // Cloud provider context
  cloud: {
    provider: 'AWS' | 'GCP' | 'Kubernetes' | 'Azure' | 'Other';
    account?: { uid?: string; name?: string };
    project_uid?: string;
    region?: string;
  };
  // Provenance: our own observable
  observables?: Array<{ name: string; type?: string; value?: string }>;
}

const SEVERITY_MAP: Record<string, { id: 1 | 2 | 3 | 4 | 5; name: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical' }> = {
  info:     { id: 1, name: 'Informational' },
  low:      { id: 2, name: 'Low' },
  medium:   { id: 3, name: 'Medium' },
  high:     { id: 4, name: 'High' },
  critical: { id: 5, name: 'Critical' },
};

const PROVIDER_MAP: Record<string, 'AWS' | 'GCP' | 'Kubernetes' | 'Other'> = {
  aws: 'AWS',
  gcp: 'GCP',
  k8s: 'Kubernetes',
};

/**
 * Build a single OCSF event from a Finding + its parent EvidenceFile.
 */
export function buildOcsfEvent(finding: Finding, evidence: EvidenceFile, scopeId: string | null, provider: string, region?: string): OcsfComplianceFinding {
  // SEVERITY_MAP.info is statically present so the non-null assert is safe.
  const sev = SEVERITY_MAP[finding.severity] ?? SEVERITY_MAP.info!;
  const ocsfProvider = PROVIDER_MAP[provider] ?? 'Other';
  return {
    metadata: {
      version: OCSF_VERSION,
      product: { name: 'fedramp-20x-cloud-evidence', vendor_name: 'self-hosted', version: '0.1.0', lang: 'en' },
      profiles: ['cloud', 'compliance'],
    },
    category_uid: 2,
    category_name: 'Findings',
    class_uid: OCSF_COMPLIANCE_FINDING_CLASS_UID,
    class_name: 'Compliance Finding',
    type_uid: 200301,
    type_name: 'Compliance Finding: Create',
    severity_id: sev.id,
    severity: sev.name,
    status_id: finding.passed ? 2 : 1,
    status: finding.passed ? 'In Progress' : 'New',
    activity_id: 1,
    activity_name: 'Create',
    time: new Date(evidence.collected_at).getTime(),
    compliance: {
      requirements: finding.nist_controls ?? [],
      standards: ['FedRAMP 20x'],
      control: evidence.ksi_id,
      status: finding.passed ? 'Pass' : 'Fail',
      status_detail: finding.current_state?.summary,
    },
    finding_info: {
      title: `${evidence.ksi_id} — ${finding.rule}`,
      desc: finding.current_state?.summary ?? evidence.ksi_statement,
      uid: `${evidence.ksi_id}|${finding.rule}|${provider}|${scopeId ?? '-'}`,
      types: ['compliance_finding'],
    },
    resources: finding.gap?.affected_resources?.slice(0, 50).map((r) => ({
      uid: r.identifier,
      name: r.name ?? r.identifier,
      type: r.type,
      region: region,
    })),
    cloud: {
      provider: ocsfProvider,
      account: scopeId ? { uid: scopeId } : undefined,
      project_uid: provider === 'gcp' ? scopeId ?? undefined : undefined,
      region,
    },
    observables: [
      { name: 'run_id', type: 'string', value: evidence.run_id },
      { name: 'frmr_version', type: 'string', value: evidence.frmr_version },
    ],
  };
}

// ---- HTTP helper ----

export interface HttpPostFn {
  (url: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }>;
}

function defaultHttp(url: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? httpsRequest : httpRequest;
    const req = lib({
      method: 'POST',
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      timeout: 30_000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('SIEM HTTP request timed out')); });
    req.write(body);
    req.end();
  });
}

// ---- Public API ----

export interface SiemPushOptions {
  /** Target URL (Splunk HEC, Datadog intake, generic). */
  url: string;
  /** Authorization header (e.g. "Splunk <token>" or "Bearer <token>"). */
  authHeader?: string;
  /** Optional headers (e.g. `dd-api-key` for Datadog). */
  extraHeaders?: Record<string, string>;
  /** Events per batch. Default 100. */
  batchSize?: number;
  /** Override the HTTP poster for tests. */
  httpPost?: HttpPostFn;
  /**
   * Format of the wire payload. Default 'ocsf-jsonl' (newline-separated JSON).
   * Splunk HEC wants 'splunk-hec' (objects wrapped in { event, sourcetype }).
   */
  format?: 'ocsf-jsonl' | 'splunk-hec' | 'ocsf-array';
}

export interface SiemPushResult {
  batches_sent: number;
  events_sent: number;
  failures: Array<{ batch_index: number; status?: number; reason?: string }>;
}

/**
 * Serialize a batch of events into the chosen wire format.
 */
function serializeBatch(events: OcsfComplianceFinding[], format: NonNullable<SiemPushOptions['format']>): string {
  if (format === 'ocsf-jsonl') return events.map((e) => JSON.stringify(e)).join('\n');
  if (format === 'ocsf-array') return JSON.stringify(events);
  if (format === 'splunk-hec') return events.map((e) => JSON.stringify({ event: e, sourcetype: 'fedramp-20x:ocsf' })).join('\n');
  return JSON.stringify(events);
}

export async function pushToSiem(events: OcsfComplianceFinding[], opts: SiemPushOptions): Promise<SiemPushResult> {
  const batchSize = opts.batchSize ?? 100;
  const format = opts.format ?? 'ocsf-jsonl';
  const post = opts.httpPost ?? defaultHttp;
  const headers: Record<string, string> = {
    'content-type': format === 'ocsf-array' ? 'application/json' : 'application/x-ndjson',
    ...(opts.extraHeaders ?? {}),
  };
  if (opts.authHeader) headers.authorization = opts.authHeader;

  const result: SiemPushResult = { batches_sent: 0, events_sent: 0, failures: [] };

  for (let i = 0; i < events.length; i += batchSize) {
    const batch = events.slice(i, i + batchSize);
    const body = serializeBatch(batch, format);
    try {
      const res = await withRetry(() => post(opts.url, headers, body), { attempts: 3, baseDelayMs: 200, maxDelayMs: 2000 });
      if (res.status >= 200 && res.status < 300) {
        result.batches_sent++;
        result.events_sent += batch.length;
      } else {
        result.failures.push({ batch_index: i / batchSize, status: res.status, reason: res.body.slice(0, 200) });
        log.warn({ event: 'siem.batch_failed', batch_index: i / batchSize, status: res.status });
      }
    } catch (e: any) {
      // Differentiate connection-refused / DNS / timeout so the operator knows
      // whether to check the URL, network egress, or the SIEM's availability.
      const code = e?.code ?? e?.cause?.code;
      const reason = code ? `${code}: ${e?.message ?? ''}`.trim() : (e?.message ?? String(e));
      result.failures.push({ batch_index: i / batchSize, reason });
      log.warn({ event: 'siem.batch_exception', err_code: code, err_message: e?.message });
    }
  }

  log.info({ event: 'siem.push_complete', ...result });
  return result;
}

/**
 * Convenience: build events for every Finding in an EvidenceFile + push.
 */
export async function pushEvidenceToSiem(evidence: EvidenceFile, opts: SiemPushOptions): Promise<SiemPushResult> {
  const events: OcsfComplianceFinding[] = [];
  for (const p of evidence.providers) {
    const region = (p.region_set ?? [])[0];
    const scopeId = p.account_id ?? p.project_id ?? null;
    for (const f of p.findings) {
      events.push(buildOcsfEvent(f, evidence, scopeId, p.provider, region));
    }
  }
  return pushToSiem(events, opts);
}
