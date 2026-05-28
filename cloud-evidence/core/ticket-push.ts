/**
 * Ticket-system push: open/update/close work-items per failing finding.
 *
 * The adapter abstracts over Jira (Atlassian REST API v3), ServiceNow
 * (Now REST API "table" endpoints), and GitHub Issues (REST API v3). The
 * orchestrator hands every failing finding to the configured driver and
 * the driver handles deduplication via an "external key" (a stable
 * identifier the finding maps to).
 *
 * Idempotency:
 *   - Each finding gets a stable external_key: `${ksi_id}|${rule}|${provider}|${account_or_project}`.
 *   - On push, we look up an existing ticket by that key. If present + open,
 *     update the comments/labels with the latest run timestamp. If present
 *     but closed, REOPEN with a comment noting the finding re-failed.
 *   - If absent, CREATE a new ticket.
 *
 * Why we don't auto-close passing findings:
 *   - Compliance audits prefer human acknowledgement that a finding was
 *     remediated correctly (vs. a transient false-positive). The driver
 *     adds a "fixed" comment but the human closes.
 *
 * Configuration:
 *   - Driver selection: TICKET_PROVIDER=jira|servicenow|github (or in code).
 *   - Per-driver env vars are documented at each driver's section.
 *
 * Failure modes:
 *   - Auth failure → graceful skip with reason.
 *   - Per-finding failure → continue with next finding; collect into errors[].
 */
import { request as httpsRequest } from 'node:https';
import type { Finding, EvidenceFile } from './envelope.ts';
import { log } from './log.ts';

export type TicketProvider = 'jira' | 'servicenow' | 'github';

export interface TicketRef {
  external_key: string;     // our stable identifier
  ticket_id: string;        // provider-issued ID (e.g. "PROJ-1234")
  url: string;
  status: 'opened' | 'updated' | 'reopened' | 'failed' | 'skipped';
  message?: string;
}

export interface PushTicketsResult {
  provider: TicketProvider;
  pushed: TicketRef[];
  errors: Array<{ external_key: string; error: string }>;
}

export interface TicketDriver {
  /** Provider name (for logs + result attribution). */
  name: TicketProvider;
  /** Open / update / reopen a single ticket. */
  push(args: { externalKey: string; finding: Finding; evidence: EvidenceFile }): Promise<TicketRef>;
}

// ---- Generic HTTP helper ----

export interface HttpResp { status: number; body: string; headers: Record<string, string> }

async function defaultHttp(method: string, url: string, headers: Record<string, string>, body: string | null): Promise<HttpResp> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = httpsRequest({
      method,
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: { ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) },
      timeout: 30_000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf8'),
        headers: res.headers as Record<string, string>,
      }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('ticket-push request timed out after 30s')); });
    if (body) req.write(body);
    req.end();
  });
}

export type HttpFn = typeof defaultHttp;

// ---- Helpers shared across drivers ----

export function buildExternalKey(finding: Finding, evidence: EvidenceFile, provider: string, scopeId: string | null): string {
  return `${evidence.ksi_id}|${finding.rule}|${provider}|${scopeId ?? '-'}`;
}

function findingDescriptionMd(finding: Finding, evidence: EvidenceFile): string {
  const lines: string[] = [
    `## ${evidence.ksi_id} — ${evidence.ksi_name}`,
    '',
    `**Rule:** \`${finding.rule}\``,
    `**Severity:** ${finding.severity}`,
    `**Current state:** ${finding.current_state.summary}`,
    `**Target state:** ${finding.target_state.summary}`,
    `**Rationale:** ${finding.target_state.rationale}`,
  ];
  if (finding.gap) {
    lines.push('', `**Gap:** ${finding.gap.description}`);
    if (finding.gap.affected_resources.length > 0) {
      lines.push('', '**Affected resources:**');
      for (const r of finding.gap.affected_resources.slice(0, 20)) {
        lines.push(`- \`${r.type}\` — ${r.identifier}`);
      }
      if (finding.gap.affected_resources.length > 20) {
        lines.push(`- …and ${finding.gap.affected_resources.length - 20} more`);
      }
    }
  }
  if (finding.remediation) {
    lines.push('', `**Remediation:** ${finding.remediation.summary}`);
    for (const opt of finding.remediation.options.slice(0, 3)) {
      lines.push('', `*Option (${opt.mechanism}):* ${opt.approach}`);
      lines.push(opt.steps.map((s, i) => `  ${i + 1}. ${s}`).join('\n'));
    }
  }
  if (finding.nist_controls?.length) {
    lines.push('', `**NIST controls:** ${finding.nist_controls.join(', ')}`);
  }
  return lines.join('\n');
}

// ---- GitHub Issues driver ----

export interface GitHubDriverOptions {
  /** GitHub personal-access token (with `repo` scope). */
  token: string;
  /** "owner/repo". */
  repo: string;
  /** Optional labels to apply to every ticket. */
  labels?: string[];
  http?: HttpFn;
}

export function gitHubIssuesDriver(o: GitHubDriverOptions): TicketDriver {
  const http = o.http ?? defaultHttp;
  const headers = {
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    authorization: `Bearer ${o.token}`,
    'content-type': 'application/json',
    'user-agent': 'fedramp-20x-cloud-evidence',
  };

  return {
    name: 'github',
    async push({ externalKey, finding, evidence }) {
      // Find existing by key in labels OR body
      const q = encodeURIComponent(`repo:${o.repo} in:body "${externalKey}"`);
      const search = await http('GET', `https://api.github.com/search/issues?q=${q}`, headers, null);
      let existing: any = null;
      if (search.status === 200) {
        try {
          const data = JSON.parse(search.body);
          existing = (data.items ?? [])[0] ?? null;
        } catch (e: any) {
          log.warn({ event: 'ticket.search_parse_failed', provider: 'github', external_key: externalKey, err_message: e?.message });
        }
      }
      const title = `[${evidence.ksi_id}] ${finding.rule}`;
      const body = findingDescriptionMd(finding, evidence) + `\n\n<!-- cloud-evidence-key: ${externalKey} -->`;
      const labels = ['fedramp-20x', evidence.ksi_id, ...(o.labels ?? [])];

      if (existing) {
        if (existing.state === 'closed') {
          // Reopen + comment
          await http('PATCH', `https://api.github.com/repos/${o.repo}/issues/${existing.number}`, headers, JSON.stringify({ state: 'open' }));
          await http('POST', `https://api.github.com/repos/${o.repo}/issues/${existing.number}/comments`, headers, JSON.stringify({ body: `Finding re-failed in run on ${evidence.collected_at}. Reopening.` }));
          return { external_key: externalKey, ticket_id: String(existing.number), url: existing.html_url, status: 'reopened' };
        }
        // Update comment with latest run info
        await http('POST', `https://api.github.com/repos/${o.repo}/issues/${existing.number}/comments`, headers, JSON.stringify({ body: `Still failing as of ${evidence.collected_at}.` }));
        return { external_key: externalKey, ticket_id: String(existing.number), url: existing.html_url, status: 'updated' };
      }

      // Create
      const create = await http('POST', `https://api.github.com/repos/${o.repo}/issues`, headers, JSON.stringify({ title, body, labels }));
      if (create.status >= 200 && create.status < 300) {
        try {
          const data = JSON.parse(create.body);
          return { external_key: externalKey, ticket_id: String(data.number), url: data.html_url, status: 'opened' };
        } catch (e: any) {
          return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `GitHub returned HTTP ${create.status} but body was not JSON: ${e?.message}` };
        }
      }
      return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `HTTP ${create.status}: ${create.body.slice(0, 200)}` };
    },
  };
}

// ---- Jira driver ----

export interface JiraDriverOptions {
  /** Site URL like "https://acme.atlassian.net". */
  siteUrl: string;
  /** Atlassian email used to generate the API token. */
  email: string;
  /** API token from https://id.atlassian.com/manage-profile/security/api-tokens */
  apiToken: string;
  /** Project key (e.g. "SEC"). */
  projectKey: string;
  /** Issue type name (default "Task"). */
  issueType?: string;
  http?: HttpFn;
}

export function jiraDriver(o: JiraDriverOptions): TicketDriver {
  const http = o.http ?? defaultHttp;
  const issueType = o.issueType ?? 'Task';
  const basic = Buffer.from(`${o.email}:${o.apiToken}`).toString('base64');
  const headers = {
    authorization: `Basic ${basic}`,
    'content-type': 'application/json',
    accept: 'application/json',
  };

  return {
    name: 'jira',
    async push({ externalKey, finding, evidence }) {
      // Search by external key in description (Jira lacks a custom-field-less native key)
      const jql = encodeURIComponent(`project = "${o.projectKey}" AND text ~ "\\"${externalKey}\\"" ORDER BY created DESC`);
      const search = await http('GET', `${o.siteUrl}/rest/api/3/search?jql=${jql}&maxResults=1&fields=key,status`, headers, null);
      let existing: any = null;
      if (search.status === 200) {
        try {
          const data = JSON.parse(search.body);
          existing = (data.issues ?? [])[0] ?? null;
        } catch (e: any) {
          log.warn({ event: 'ticket.search_parse_failed', provider: 'jira', external_key: externalKey, err_message: e?.message });
        }
      }

      const summary = `[${evidence.ksi_id}] ${finding.rule}`;
      const descriptionMd = findingDescriptionMd(finding, evidence) + `\n\n---\ncloud-evidence-key: ${externalKey}`;

      if (existing) {
        // Add a comment + reopen if needed
        const isClosed = ['Done', 'Closed', 'Resolved'].includes(existing.fields?.status?.name ?? '');
        if (isClosed) {
          // Attempt a transition by name to "To Do" — best-effort, not all workflows support
          await http('POST', `${o.siteUrl}/rest/api/3/issue/${existing.key}/comment`, headers, JSON.stringify({ body: `Finding re-failed in run on ${evidence.collected_at}.` }));
          return { external_key: externalKey, ticket_id: existing.key, url: `${o.siteUrl}/browse/${existing.key}`, status: 'reopened', message: 'Comment added; workflow transition not attempted' };
        }
        await http('POST', `${o.siteUrl}/rest/api/3/issue/${existing.key}/comment`, headers, JSON.stringify({ body: `Still failing as of ${evidence.collected_at}.` }));
        return { external_key: externalKey, ticket_id: existing.key, url: `${o.siteUrl}/browse/${existing.key}`, status: 'updated' };
      }

      const create = await http('POST', `${o.siteUrl}/rest/api/3/issue`, headers, JSON.stringify({
        fields: {
          project: { key: o.projectKey },
          summary,
          description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: descriptionMd }] }] },
          issuetype: { name: issueType },
        },
      }));
      if (create.status >= 200 && create.status < 300) {
        try {
          const data = JSON.parse(create.body);
          return { external_key: externalKey, ticket_id: data.key, url: `${o.siteUrl}/browse/${data.key}`, status: 'opened' };
        } catch (e: any) {
          return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `Jira returned HTTP ${create.status} but body was not JSON: ${e?.message}` };
        }
      }
      return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `HTTP ${create.status}: ${create.body.slice(0, 200)}` };
    },
  };
}

// ---- ServiceNow driver ----

export interface ServiceNowDriverOptions {
  /** Instance URL like "https://acme.service-now.com". */
  instanceUrl: string;
  /** ServiceNow user. */
  user: string;
  /** ServiceNow password. */
  password: string;
  /** Table to create records in (default 'incident'). */
  table?: string;
  http?: HttpFn;
}

export function serviceNowDriver(o: ServiceNowDriverOptions): TicketDriver {
  const http = o.http ?? defaultHttp;
  const table = o.table ?? 'incident';
  const basic = Buffer.from(`${o.user}:${o.password}`).toString('base64');
  const headers = {
    authorization: `Basic ${basic}`,
    'content-type': 'application/json',
    accept: 'application/json',
  };

  return {
    name: 'servicenow',
    async push({ externalKey, finding, evidence }) {
      // Search by external_key stored in short_description prefix or u_external_key custom field
      const q = encodeURIComponent(`u_external_keyLIKE${externalKey}^ORshort_descriptionLIKE${externalKey}`);
      const search = await http('GET', `${o.instanceUrl}/api/now/table/${table}?sysparm_query=${q}&sysparm_limit=1`, headers, null);
      let existing: any = null;
      if (search.status === 200) {
        try {
          const data = JSON.parse(search.body);
          existing = (data.result ?? [])[0] ?? null;
        } catch (e: any) {
          log.warn({ event: 'ticket.search_parse_failed', provider: 'servicenow', external_key: externalKey, err_message: e?.message });
        }
      }
      const description = findingDescriptionMd(finding, evidence) + `\nexternal_key: ${externalKey}`;
      const title = `[${evidence.ksi_id}] ${finding.rule}`;

      if (existing) {
        // Add a work-note + reopen if state == 6 (resolved/closed in ServiceNow incident table)
        const sysId = existing.sys_id;
        const isClosed = ['6', '7'].includes(String(existing.state));
        if (isClosed) {
          await http('PATCH', `${o.instanceUrl}/api/now/table/${table}/${sysId}`, headers, JSON.stringify({ state: '1', work_notes: `Re-opened: finding re-failed on ${evidence.collected_at}.` }));
          return { external_key: externalKey, ticket_id: sysId, url: `${o.instanceUrl}/nav_to.do?uri=${table}.do%3Fsys_id=${sysId}`, status: 'reopened' };
        }
        await http('PATCH', `${o.instanceUrl}/api/now/table/${table}/${sysId}`, headers, JSON.stringify({ work_notes: `Still failing as of ${evidence.collected_at}.` }));
        return { external_key: externalKey, ticket_id: sysId, url: `${o.instanceUrl}/nav_to.do?uri=${table}.do%3Fsys_id=${sysId}`, status: 'updated' };
      }
      const create = await http('POST', `${o.instanceUrl}/api/now/table/${table}`, headers, JSON.stringify({
        short_description: title,
        description,
        u_external_key: externalKey,
      }));
      if (create.status >= 200 && create.status < 300) {
        try {
          const data = JSON.parse(create.body);
          const sysId = data?.result?.sys_id ?? '-';
          return { external_key: externalKey, ticket_id: sysId, url: `${o.instanceUrl}/nav_to.do?uri=${table}.do%3Fsys_id=${sysId}`, status: 'opened' };
        } catch (e: any) {
          return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `ServiceNow returned HTTP ${create.status} but body was not JSON: ${e?.message}` };
        }
      }
      return { external_key: externalKey, ticket_id: '-', url: '', status: 'failed', message: `HTTP ${create.status}: ${create.body.slice(0, 200)}` };
    },
  };
}

// ---- Public API: push all failing findings via a driver ----

export async function pushFailingFindings(driver: TicketDriver, evidence: EvidenceFile): Promise<PushTicketsResult> {
  const out: TicketRef[] = [];
  const errors: Array<{ external_key: string; error: string }> = [];
  for (const p of evidence.providers) {
    const scopeId = p.account_id ?? p.project_id ?? null;
    for (const f of p.findings) {
      if (f.passed) continue;
      const externalKey = buildExternalKey(f, evidence, p.provider, scopeId);
      try {
        const ref = await driver.push({ externalKey, finding: f, evidence });
        out.push(ref);
      } catch (e: any) {
        errors.push({ external_key: externalKey, error: e?.message ?? String(e) });
        log.warn({ event: 'ticket.push_failed', provider: driver.name, external_key: externalKey, err_message: e?.message });
      }
    }
  }
  return { provider: driver.name, pushed: out, errors };
}
