/**
 * ADS endpoint probe — Authorization Data Sharing public-surface checker.
 *
 * Per docs/analysis/ads-mas-csx.md, the genuinely automatable part of the ADS
 * family is the *existence and reachability* of the CSP's public authorization
 * surface: the public CSO page (ADS-CSO-PUB), the service list (ADS-CSO-SVC),
 * the Trust Center (ADS-CSX-UTC / ADS-CSL-UTC), the programmatic API
 * (ADS-TRC-PAC), the human + machine-readable variants (ADS-TRC-HMR), and the
 * public access-guidance page (ADS-UTC-PGD). All of these are observable over a
 * read-only HTTPS GET/HEAD: status, content-type, latency, and — for the CSO
 * page — a field-presence checklist against ADS-CSO-PUB's 13 required fields.
 *
 * STRICTLY READ-ONLY: outbound probes are GET/HEAD only, no credentials, no
 * mutation. Network failures NEVER throw — the result carries reachable:false
 * with a clear reason so the requirement degrades to a warning / missing
 * evidence (unreachable ≠ noncompliant), never a crash or a silent pass.
 *
 * The HTTP function is dependency-injected (opts.fetchImpl) so tests run fully
 * offline; it defaults to the global fetch, wrapped in core/retry.withRetry
 * with a timeout via AbortController.
 */
import type { Finding, ImpactTier, KeyWord, AffectedResource } from './envelope.ts';
import { finding, severityForKeyWord } from './findings.ts';
import { withRetry } from './retry.ts';
import { log } from './log.ts';

/**
 * ADS-CSO-PUB's 13-field checklist (from the analysis). Each entry is a label
 * plus the regexes that, if any match the fetched body, count the field present.
 */
export const ADS_CSO_PUB_FIELDS: Array<{ key: string; label: string; patterns: RegExp[] }> = [
  { key: 'marketplace_link', label: 'FedRAMP Marketplace link', patterns: [/marketplace\.fedramp\.gov/i] },
  { key: 'service_model', label: 'Service Model', patterns: [/\b(SaaS|PaaS|IaaS|service model)\b/i] },
  { key: 'deployment_model', label: 'Deployment Model', patterns: [/\b(public cloud|government cloud|gov cloud|deployment model|hybrid cloud)\b/i] },
  { key: 'business_category', label: 'Business Category', patterns: [/business category/i] },
  { key: 'uei', label: 'UEI number', patterns: [/\bUEI\b/i, /unique entity id/i, /\b[A-Z0-9]{12}\b/] },
  { key: 'contact_info', label: 'Contact info', patterns: [/contact/i, /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i] },
  { key: 'service_description', label: 'Overall service description', patterns: [/service description/i, /overview/i] },
  { key: 'service_list', label: 'Detailed service list (ADS-CSO-SVC)', patterns: [/service list/i, /services?\b/i] },
  { key: 'customer_responsibility', label: 'Customer-responsibility / secure-config summary', patterns: [/customer responsibilit/i, /secure configuration/i, /shared responsibilit/i] },
  { key: 'trust_center_access', label: 'Trust Center access process', patterns: [/trust center/i, /request access/i] },
  { key: 'trust_center_status', label: 'Trust Center availability status + support', patterns: [/availability/i, /status/i, /support/i] },
  { key: 'oar_date', label: 'Next OAR date (CCM-OAR-NRD)', patterns: [/OAR/i, /ongoing authorization/i, /\b20\d{2}-\d{2}-\d{2}\b/] },
  { key: 'machine_readable', label: 'Machine-readable variant link (OSCAL/JSON)', patterns: [/oscal/i, /\.json\b/i, /application\/json/i] },
];

/** What kind of ADS surface a URL represents — drives which checks run. */
export type AdsEndpointKind = 'cso_page' | 'service_list' | 'trust_center' | 'api' | 'oscal' | 'guidance' | 'generic';

export interface AdsProbeTarget {
  url: string;
  /** What this URL is (defaults to 'generic'). Drives the field checklist (cso_page) etc. */
  kind?: AdsEndpointKind;
  /** Friendly label for findings (defaults to the URL). */
  label?: string;
}

/** Injected HTTP response shape (subset of the WHATWG Response we use). */
export interface ProbeResponse {
  ok: boolean;
  status: number;
  /** Returns a header value or null. */
  headerGet: (name: string) => string | null;
  /** Resolves the response body as text (may be empty for HEAD). */
  text: () => Promise<string>;
}

/** Dependency-injected fetch: a GET/HEAD to `url`. MUST be read-only. */
export type ProbeFetch = (
  url: string,
  init: { method: 'GET' | 'HEAD'; signal: AbortSignal; headers: Record<string, string> },
) => Promise<ProbeResponse>;

export interface ProbeAdsOptions {
  /** URLs to probe. If a bare string, treated as a generic endpoint. */
  urls: Array<string | AdsProbeTarget>;
  /** Per-request timeout in ms (default 8000). */
  timeoutMs?: number;
  /** Retry attempts for transient failures (default 2). */
  attempts?: number;
  /** Injected HTTP function (defaults to a global-fetch adapter). Tests pass a fake. */
  fetchImpl?: ProbeFetch;
}

export interface AdsEndpointResult {
  url: string;
  kind: AdsEndpointKind;
  label: string;
  reachable: boolean;
  /** HTTP status (0 when unreachable). */
  status: number;
  /** Lowercased content-type, if any. */
  content_type: string | null;
  /** Round-trip latency in ms. */
  latency_ms: number;
  /** Populated when reachable:false — DNS/timeout/non-2xx/etc. */
  reason?: string;
  /**
   * For cso_page kind: the 13-field presence checklist result.
   * present/missing list field keys; satisfied is present.length === total.
   */
  field_checklist?: {
    present: string[];
    missing: string[];
    total: number;
    satisfied: boolean;
  };
  /** True when an auth wall (401/403/redirect-to-login) was detected (API kind treats this as "present, gated"). */
  auth_gated?: boolean;
}

export interface AdsProbeResult {
  endpoints: AdsEndpointResult[];
  /** Whether any URL was supplied at all. */
  had_urls: boolean;
  counts: { total: number; reachable: number; unreachable: number };
}

const DEFAULT_TIMEOUT_MS = 8000;

/** Default fetch adapter over the global fetch, normalizing to ProbeResponse. */
function defaultFetchImpl(): ProbeFetch {
  return async (url, init) => {
    const resp = await fetch(url, { method: init.method, signal: init.signal, headers: init.headers, redirect: 'manual' });
    return {
      ok: resp.ok,
      status: resp.status,
      headerGet: (n: string) => resp.headers.get(n),
      text: () => resp.text(),
    };
  };
}

/** Resolve the env-supplied URL list (CLOUD_EVIDENCE_ADS_URLS, comma/newline separated). */
export function adsUrlsFromEnv(): string[] {
  const raw = process.env.CLOUD_EVIDENCE_ADS_URLS;
  if (!raw) return [];
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function normalizeTargets(urls: Array<string | AdsProbeTarget>): AdsProbeTarget[] {
  return (urls ?? [])
    .map((u) => (typeof u === 'string' ? { url: u } : u))
    .filter((t) => t && typeof t.url === 'string' && t.url.trim().length > 0)
    .map((t) => ({ url: t.url.trim(), kind: t.kind ?? 'generic', label: t.label ?? t.url.trim() }));
}

/** Run the 13-field checklist against a fetched HTML/JSON body. */
function runFieldChecklist(body: string): NonNullable<AdsEndpointResult['field_checklist']> {
  const present: string[] = [];
  const missing: string[] = [];
  for (const f of ADS_CSO_PUB_FIELDS) {
    if (f.patterns.some((re) => re.test(body))) present.push(f.key);
    else missing.push(f.key);
  }
  return { present, missing, total: ADS_CSO_PUB_FIELDS.length, satisfied: missing.length === 0 };
}

/**
 * Probe a single ADS endpoint. NEVER throws — returns reachable:false + reason
 * on any failure. cso_page/service_list/oscal/generic use GET (need the body
 * for the checklist / content-type); trust_center/api/guidance also GET so we
 * can sniff content and keywords.
 */
async function probeOne(target: AdsProbeTarget, opts: Required<Pick<ProbeAdsOptions, 'timeoutMs' | 'attempts'>>, fetchImpl: ProbeFetch): Promise<AdsEndpointResult> {
  const kind = target.kind ?? 'generic';
  const label = target.label ?? target.url;
  const base: AdsEndpointResult = { url: target.url, kind, label, reachable: false, status: 0, content_type: null, latency_ms: 0 };

  // Reject obviously non-HTTPS targets up front (read-only + secure surface only).
  if (!/^https?:\/\//i.test(target.url)) {
    return { ...base, reason: `Not an HTTP(S) URL: "${target.url}". ADS surfaces must be reachable over HTTPS.` };
  }

  const t0 = Date.now();
  try {
    const resp = await withRetry(
      async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
        try {
          const r = await fetchImpl(target.url, {
            method: 'GET',
            signal: controller.signal,
            headers: { accept: 'text/html,application/json;q=0.9,*/*;q=0.8' },
          });
          // Surface HTTP status in the AWS-SDK shape so retry classifies 5xx/429.
          if (!r.ok && (r.status === 429 || (r.status >= 500 && r.status < 600))) {
            throw Object.assign(new Error(`ADS endpoint HTTP ${r.status}`), { $metadata: { httpStatusCode: r.status }, _resp: r });
          }
          return r;
        } finally {
          clearTimeout(timer);
        }
      },
      { attempts: opts.attempts, baseDelayMs: 400, maxDelayMs: 3000 },
    );

    const latency_ms = Date.now() - t0;
    const contentType = (resp.headerGet('content-type') ?? '').toLowerCase() || null;
    const authGated = resp.status === 401 || resp.status === 403 || (resp.status >= 300 && resp.status < 400);

    // For an API endpoint, 401/403 means "present but access-gated" → reachable.
    const reachable = resp.ok || (kind === 'api' && (resp.status === 401 || resp.status === 403));

    let body = '';
    if (reachable && kind !== 'api') {
      try {
        body = await resp.text();
      } catch {
        body = '';
      }
    }

    const result: AdsEndpointResult = {
      ...base,
      reachable,
      status: resp.status,
      content_type: contentType,
      latency_ms,
      auth_gated: authGated || undefined,
    };

    if (!reachable) {
      result.reason = authGated
        ? `Endpoint returned ${resp.status} (auth wall / redirect) — not anonymously reachable.`
        : `Endpoint returned non-2xx status ${resp.status}.`;
      return result;
    }

    if (kind === 'cso_page') {
      result.field_checklist = runFieldChecklist(body);
    }
    return result;
  } catch (e) {
    // Per the analysis: unreachable is a WARNING, never a crash and never a fail-by-itself.
    const msg = (e as Error)?.message ?? String(e);
    log.warn({ event: 'ads.probe.fail', url: target.url, err: msg });
    return { ...base, latency_ms: Date.now() - t0, reason: `Probe failed (no compliance judgment): ${msg}` };
  }
}

/**
 * Probe one or more ADS public endpoints, read-only. Resolves to a result for
 * every supplied URL; never rejects. If `urls` is empty, falls back to
 * CLOUD_EVIDENCE_ADS_URLS; if that is also empty, returns had_urls:false so the
 * caller can emit missing_evidence rather than a false pass.
 */
export async function probeAdsEndpoints(opts: ProbeAdsOptions): Promise<AdsProbeResult> {
  const supplied = normalizeTargets(opts.urls);
  const targets = supplied.length > 0 ? supplied : normalizeTargets(adsUrlsFromEnv());
  const fetchImpl = opts.fetchImpl ?? defaultFetchImpl();
  const resolved = {
    timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    attempts: Math.max(1, opts.attempts ?? 2),
  };

  if (targets.length === 0) {
    return { endpoints: [], had_urls: false, counts: { total: 0, reachable: 0, unreachable: 0 } };
  }

  const endpoints = await Promise.all(targets.map((t) => probeOne(t, resolved, fetchImpl)));
  const reachable = endpoints.filter((e) => e.reachable).length;
  return {
    endpoints,
    had_urls: true,
    counts: { total: endpoints.length, reachable, unreachable: endpoints.length - reachable },
  };
}

/**
 * Obligation strength for the probeable ADS surface. ADS-TRC-HMR / ADS-TRC-RSP
 * are SHOULD; the anchor probeable requirements this module emits against
 * (CSO-PUB, CSO-SVC, CSX-UTC, TRC-PAC, UTC-PGD) are all MUST.
 */
function adsKeyWord(_kind: AdsEndpointKind): KeyWord {
  return 'MUST';
}

const ADS_NIST_CONTROLS: string[] = []; // ADS requirements carry controls[]=∅ (High derived-rev5-pending).

function endpointAffected(e: AdsEndpointResult): AffectedResource {
  return {
    type: 'fedramp_ads_endpoint',
    identifier: e.url,
    name: e.label,
    attributes: { kind: e.kind, status: e.status, content_type: e.content_type, reason: e.reason ?? null },
  };
}

/**
 * Build ADS findings from a probe result (ADS-CSO-PUB / ADS-CSO-SVC etc.).
 *
 * Emits:
 *   - one reachability finding per endpoint (unreachable → reduced-severity
 *     warning, since unreachable ≠ noncompliant per the analysis);
 *   - for any cso_page, an additional field-checklist finding (missing required
 *     fields → fail);
 *   - a missing-evidence finding when no URLs were configured at all.
 *
 * Never throws. Findings are schema-valid with rich current_state, target,
 * gap+remediation, and applicable_key_word set per tier obligation.
 */
export function buildAdsFindings(result: AdsProbeResult, tier: ImpactTier): Finding[] {
  const findings: Finding[] = [];

  if (!result.had_urls) {
    findings.push(
      finding({
        rule: 'ads.cso.pub.endpoints_configured',
        passed: false,
        severity: severityForKeyWord('MUST', 'high'),
        applicable_key_word: 'MUST',
        current: {
          summary: 'No ADS endpoints configured — set CLOUD_EVIDENCE_ADS_URLS or pass urls[] to probe the public authorization surface.',
          observations: { had_urls: false },
        },
        target: {
          summary: 'The CSP\'s public CSO page / Trust Center / OSCAL endpoint URLs are configured so the collector can probe their reachability and required fields.',
          rationale:
            'FedRAMP 20x ADS-CSO-PUB requires publicly sharing up-to-date CSO info in human- and machine-readable formats; the collector can only check this if the public URLs are supplied. ' +
            'ADS controls[]=∅ (High applicability derived-rev5-pending).',
        },
        gap: {
          description: 'No public ADS URL was supplied, so reachability and the 13-field checklist could not be evaluated. This is missing evidence, not a confirmed failure.',
          affected_resources: [{ type: 'fedramp_ads_endpoint', identifier: 'none', name: 'ADS public surface', attributes: { configured: false } }],
        },
        remediation: {
          summary: 'Configure the public ADS URLs.',
          options: [
            {
              approach: 'Set CLOUD_EVIDENCE_ADS_URLS to the public CSO page / Trust Center / OSCAL endpoints.',
              mechanism: 'process',
              owner_team: 'Compliance',
              steps: [
                'Identify the public CSO page, Trust Center, and machine-readable (OSCAL/JSON) URLs.',
                'Set CLOUD_EVIDENCE_ADS_URLS (comma- or newline-separated) or pass them as urls[] with a kind hint (cso_page, trust_center, api, oscal, guidance).',
                'Re-run cloud-evidence to probe reachability + the ADS-CSO-PUB field checklist.',
              ],
              cost_impact: { level: 'none', notes: 'Configuration only.' },
              availability_impact: { level: 'none', notes: 'Read-only outbound probe.' },
              customer_visible: { level: 'none', notes: 'Internal.' },
              effort_estimate: { magnitude: 'minutes', notes: 'One-time config.' },
            },
          ],
        },
        nist_controls: ADS_NIST_CONTROLS,
        note: 'ADS surfaces are frequently a third-party Trust Center (Paramify, SafeBase, Vanta); supply that vendor URL. High applicability is derived-rev5-pending.',
      }),
    );
    return findings;
  }

  for (const e of result.endpoints) {
    const kw = adsKeyWord(e.kind);
    // Reachability: unreachable is a reduced-severity advisory (warning), not a
    // hard MUST failure, because per the analysis unreachable ≠ noncompliant.
    findings.push(
      finding({
        rule: `ads.endpoint.reachable.${e.kind}`,
        passed: e.reachable,
        severity: e.reachable ? 'info' : 'medium',
        applicable_key_word: kw,
        current: {
          summary: e.reachable
            ? `${e.label} reachable (HTTP ${e.status}, ${e.content_type ?? 'unknown content-type'}, ${e.latency_ms}ms)${e.auth_gated ? ' — access-gated API endpoint present' : ''}.`
            : `${e.label} not reachable: ${e.reason ?? 'unknown reason'}.`,
          observations: {
            url: e.url,
            kind: e.kind,
            status: e.status,
            content_type: e.content_type,
            latency_ms: e.latency_ms,
            auth_gated: e.auth_gated ?? false,
            reason: e.reason ?? null,
          },
        },
        target: {
          summary: `${e.label} is reachable over HTTPS so authorization data can be shared with all necessary parties.`,
          rationale:
            'FedRAMP 20x ADS family (ADS-CSO-PUB / ADS-CSO-SVC / ADS-CSX-UTC / ADS-TRC-PAC / ADS-UTC-PGD). ' +
            'A read-only GET confirms the public surface exists; unreachable is treated as a warning (could be transient / network) rather than confirmed noncompliance. ' +
            'ADS controls[]=∅; High applicability derived-rev5-pending.',
        },
        gap: e.reachable
          ? undefined
          : {
              description: `${e.label} could not be reached anonymously over HTTPS. Confirm the URL is correct and publicly accessible (this is an advisory, not a confirmed compliance failure).`,
              affected_resources: [endpointAffected(e)],
            },
        remediation: e.reachable
          ? undefined
          : {
              summary: 'Verify the public ADS endpoint URL and accessibility.',
              options: [
                {
                  approach: 'Confirm the URL, TLS, and public (anonymous) accessibility of the ADS surface.',
                  mechanism: 'process',
                  owner_team: 'Compliance',
                  steps: [
                    'Open the URL in a private browser to confirm it loads without authentication.',
                    'If it sits behind an auth wall, expose a public CSO page or use the Trust Center vendor\'s public trust page.',
                    'If transient (DNS/timeout), re-run; sustained failure across runs indicates a real availability gap (ADS-TRC-USH).',
                  ],
                  cost_impact: { level: 'none', notes: 'Verification effort.' },
                  availability_impact: { level: 'none', notes: 'Read-only.' },
                  customer_visible: { level: 'low', notes: 'The public surface is customer-facing.' },
                  effort_estimate: { magnitude: 'minutes', notes: 'Verification.' },
                },
              ],
            },
        alternative_satisfiers: [
          {
            via: 'Third-party FedRAMP-compatible Trust Center (Paramify, SafeBase, Vanta Trust Center)',
            description: 'A vendor Trust Center renders these fields and exposes a public + machine-readable surface; probe that URL instead.',
            evidence_required: ['Trust Center public URL', 'Vendor FedRAMP-compatibility attestation'],
            detected: false,
            detection_signals: [],
          },
        ],
        nist_controls: ADS_NIST_CONTROLS,
        note: 'Unreachable is reported as a reduced-severity advisory (unreachable ≠ noncompliant). High applicability is derived-rev5-pending.',
      }),
    );

    // Field checklist (ADS-CSO-PUB) for the public CSO page.
    if (e.kind === 'cso_page' && e.field_checklist) {
      const fc = e.field_checklist;
      findings.push(
        finding({
          rule: 'ads.cso.pub.required_fields_present',
          passed: fc.satisfied,
          severity: severityForKeyWord('MUST', 'high'),
          applicable_key_word: 'MUST',
          current: {
            summary: fc.satisfied
              ? `Public CSO page presents all ${fc.total} ADS-CSO-PUB required fields.`
              : `Public CSO page is missing ${fc.missing.length} of ${fc.total} ADS-CSO-PUB required field(s): ${fc.missing.join(', ')}.`,
            observations: { url: e.url, present: fc.present, missing: fc.missing, total: fc.total },
          },
          target: {
            summary: 'The public CSO page presents all 13 ADS-CSO-PUB required fields (Marketplace link, service/deployment model, business category, UEI, contact, description, service list, customer-responsibility summary, Trust Center access + status, OAR date, machine-readable variant).',
            rationale:
              'FedRAMP 20x ADS-CSO-PUB MUST: providers publicly share up-to-date CSO info in human- and machine-readable formats including at least the 13 listed fields. ' +
              'The presence checklist is a heuristic (regex over the fetched body) — a present field means the keyword/pattern was found, not that its content is accurate (content accuracy remains a human review). ' +
              'ADS controls[]=∅; High applicability derived-rev5-pending.',
          },
          gap: fc.satisfied
            ? undefined
            : {
                description: `Required ADS-CSO-PUB fields not detected on the public CSO page: ${fc.missing.join(', ')}. (Heuristic detection — verify these are genuinely absent vs. phrased differently.)`,
                affected_resources: fc.missing.map((k) => ({
                  type: 'fedramp_ads_required_field',
                  identifier: k,
                  name: ADS_CSO_PUB_FIELDS.find((f) => f.key === k)?.label ?? k,
                  attributes: { url: e.url },
                })),
              },
          remediation: fc.satisfied
            ? undefined
            : {
                summary: 'Add the missing required fields to the public CSO page (and its machine-readable variant).',
                options: [
                  {
                    approach: 'Publish the missing ADS-CSO-PUB fields on the public CSO page and keep the machine-readable variant consistent (ADS-CSO-CBF).',
                    mechanism: 'process',
                    owner_team: 'Compliance',
                    steps: [
                      `Add the missing fields to the public CSO page: ${fc.missing.join(', ')}.`,
                      'Mirror the fields into the machine-readable (OSCAL/JSON) variant; use automation so the two stay consistent (ADS-CSO-CBF).',
                      'Confirm the FedRAMP Marketplace link, UEI, and next OAR date are present and current.',
                      'Re-run cloud-evidence to confirm the checklist passes.',
                    ],
                    cost_impact: { level: 'none', notes: 'Content authoring.' },
                    availability_impact: { level: 'none', notes: 'No system change.' },
                    customer_visible: { level: 'medium', notes: 'The CSO page is public and customer-facing.' },
                    effort_estimate: { magnitude: 'hours', notes: 'Content + machine-readable sync.' },
                  },
                ],
              },
          nist_controls: ADS_NIST_CONTROLS,
          cross_ksi_dependencies: [
            { ksi_id: 'ADS-CSO-CBF', relationship: 'shares-remediation', note: 'Keeping the machine-readable variant consistent with the HR page is the ADS-CSO-CBF automation obligation.' },
            { ksi_id: 'ADS-CSO-SVC', relationship: 'shares-remediation', note: 'The service-list field overlaps with the ADS-CSO-SVC public service list.' },
          ],
          note: 'Field presence is heuristic (keyword/pattern match over the fetched body). Content accuracy and "up-to-date" remain human review. High applicability is derived-rev5-pending.',
        }),
      );
    }
  }

  return findings;
}
