/**
 * LLM-powered remediation PR generator.
 *
 * Given a failing Finding, ask an LLM (Anthropic Claude by default) to
 * produce a concrete Terraform / CloudFormation / Kubernetes YAML patch
 * that would close the gap. The output is a structured object containing:
 *
 *   - title          (PR-ready, e.g. "Enable MFA for IAM user bob.contractor")
 *   - body_markdown  (PR description with finding context + tradeoffs)
 *   - files: [{ path, before?, after, language }]
 *
 * Design choices:
 *   - We pass the finding's `current_state.observations` + `target_state.summary`
 *     + the first 3 remediation options as structured JSON, so the model has
 *     deterministic context. The LLM is asked to choose ONE option (or a
 *     hybrid) and produce a minimal-diff change.
 *   - The LLM is asked to respond in a strict JSON schema we validate.
 *     If parsing fails, we surface the raw text and let the caller decide.
 *   - Network calls are abstracted via `httpPost` so tests can inject
 *     deterministic responses (no real API key required).
 *
 * Cost / safety:
 *   - We DO NOT auto-commit the generated changes. The output is data —
 *     a downstream step (F.2 ticket-push or a CI pipeline) opens the PR.
 *   - Token spend is bounded: ~5K input tokens per finding (the finding
 *     itself is the biggest input, ~2-4K). Operators should batch.
 *
 * Failure modes:
 *   - No ANTHROPIC_API_KEY → return { skipped: true, reason }.
 *   - API HTTP error → return { skipped: true, reason: status+message }.
 *   - Malformed JSON → return { skipped: true, raw_text }.
 */
import { request as httpsRequest } from 'node:https';
import type { Finding, EvidenceFile } from './envelope.ts';
import { log } from './log.ts';

const DEFAULT_MODEL = 'claude-opus-4-5';
const DEFAULT_API_URL = 'https://api.anthropic.com/v1/messages';
const DEFAULT_MAX_TOKENS = 4096;

export interface GeneratedPatchFile {
  path: string;
  language: 'hcl' | 'yaml' | 'json' | 'python' | 'shell' | 'other';
  /** Existing content (omitted if the file is new). */
  before?: string;
  /** Proposed content after the change. */
  after: string;
}

export interface GeneratedPr {
  title: string;
  body_markdown: string;
  files: GeneratedPatchFile[];
  /** The mechanism the LLM chose (terraform / cloudformation / kubernetes / etc.). */
  mechanism: string;
  /** LLM-stated risks the human reviewer should validate. */
  risks: string[];
  /** Estimated effort (minutes / hours / days). */
  effort: string;
}

export interface GenerateOptions {
  finding: Finding;
  evidence: EvidenceFile;
  /** Anthropic API key. Falls back to ANTHROPIC_API_KEY env. */
  apiKey?: string;
  /** Model name. Falls back to LLM_MODEL env or claude-opus-4-5. */
  model?: string;
  /** API base URL. Override for proxies / mocks. */
  apiUrl?: string;
  /** Maximum response tokens. */
  maxTokens?: number;
  /** Optional override of the HTTP POST function (for tests). */
  httpPost?: (url: string, headers: Record<string, string>, body: string) => Promise<{ status: number; body: string }>;
}

export interface GenerateResult {
  skipped: boolean;
  reason?: string;
  raw_text?: string;
  pr?: GeneratedPr;
}

const SYSTEM_PROMPT = `You are a senior cloud-platform engineer. Given a FedRAMP 20x compliance finding,
generate a minimal, production-ready remediation change. Your output MUST be a JSON object
matching this exact schema:

{
  "title": "string (under 70 chars, present-tense imperative)",
  "body_markdown": "string (PR description: context + summary + risks)",
  "mechanism": "terraform|cloudformation|kubernetes|cli|process",
  "files": [
    { "path": "string", "language": "hcl|yaml|json|python|shell|other", "before": "optional string", "after": "string" }
  ],
  "risks": ["string", ...],
  "effort": "string (minutes/hours/days)"
}

Rules:
- Choose ONE mechanism that best fits this finding's environment.
- Files should be minimal-diff: change ONLY what the finding requires.
- If the finding can be fixed without code (e.g. enabling a service in console), set mechanism=process
  and files=[] and explain in body_markdown.
- Do not invent identifiers, ARNs, or project IDs — use placeholders like <ACCOUNT_ID> or {{user_name}}.
- Output ONLY the JSON object, no preamble, no markdown fences.`;

function defaultPost(url: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = httpsRequest({
      method: 'POST',
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
      timeout: 60_000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(new Error('LLM request timed out after 60s')); });
    req.write(body);
    req.end();
  });
}

function buildUserMessage(finding: Finding, evidence: EvidenceFile): string {
  return [
    `KSI: ${evidence.ksi_id} (${evidence.ksi_name})`,
    `Scope: ${evidence.scope}`,
    `Rule: ${finding.rule}`,
    `Severity: ${finding.severity}`,
    `Passed: ${finding.passed}`,
    '',
    `Current state: ${finding.current_state.summary}`,
    `Target state: ${finding.target_state.summary}`,
    `Rationale: ${finding.target_state.rationale}`,
    '',
    finding.gap ? `Gap: ${finding.gap.description}` : '',
    finding.gap && finding.gap.affected_resources.length > 0
      ? `Affected resources (${finding.gap.affected_resources.length}):\n` + finding.gap.affected_resources.slice(0, 10).map((r) => `  - ${r.type}: ${r.identifier}`).join('\n')
      : '',
    '',
    finding.remediation
      ? `Pre-baked remediation options the auditor knows about:\n` + finding.remediation.options.slice(0, 3).map((o, i) => `  ${i + 1}. (${o.mechanism}) ${o.approach}`).join('\n')
      : '',
    '',
    finding.nist_controls ? `NIST 800-53 controls: ${finding.nist_controls.join(', ')}` : '',
    '',
    `Observations (raw JSON, truncated):\n${JSON.stringify(finding.current_state.observations, null, 2).slice(0, 4000)}`,
    '',
    'Now produce the JSON object as specified.',
  ].filter(Boolean).join('\n');
}

function parseLlmResponse(text: string): GeneratedPr | null {
  // The Anthropic Messages API returns content[].text; try parsing as JSON.
  // Be lenient: strip markdown fences if the model included them.
  const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  try {
    const obj = JSON.parse(cleaned);
    if (typeof obj.title !== 'string' || typeof obj.body_markdown !== 'string') return null;
    if (!Array.isArray(obj.files)) return null;
    return obj as GeneratedPr;
  } catch {
    return null;
  }
}

/**
 * Generate a remediation PR for a single finding.
 */
export async function generatePrForFinding(opts: GenerateOptions): Promise<GenerateResult> {
  const apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey && !opts.httpPost) {
    return { skipped: true, reason: 'ANTHROPIC_API_KEY not set (and no httpPost override)' };
  }
  const url = opts.apiUrl ?? process.env.ANTHROPIC_API_URL ?? DEFAULT_API_URL;
  const model = opts.model ?? process.env.LLM_MODEL ?? DEFAULT_MODEL;
  const maxTokens = opts.maxTokens ?? DEFAULT_MAX_TOKENS;
  const post = opts.httpPost ?? defaultPost;

  const userMessage = buildUserMessage(opts.finding, opts.evidence);
  const requestBody = JSON.stringify({
    model,
    max_tokens: maxTokens,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userMessage }],
  });

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'anthropic-version': '2023-06-01',
  };
  if (apiKey) headers['x-api-key'] = apiKey;

  let res: { status: number; body: string };
  try {
    res = await post(url, headers, requestBody);
  } catch (e: any) {
    log.warn({ event: 'llm.http_failed', err_message: e?.message });
    return { skipped: true, reason: `HTTP error: ${e.message}` };
  }
  if (res.status !== 200) {
    log.warn({ event: 'llm.bad_status', status: res.status, body_preview: res.body.slice(0, 500) });
    return { skipped: true, reason: `Anthropic API returned HTTP ${res.status}: ${res.body.slice(0, 200)}` };
  }
  let parsed: any;
  try {
    parsed = JSON.parse(res.body);
  } catch {
    return { skipped: true, reason: 'API response was not JSON', raw_text: res.body };
  }
  const text = parsed?.content?.[0]?.text;
  if (!text) {
    return { skipped: true, reason: 'API response had no content[0].text', raw_text: JSON.stringify(parsed) };
  }
  const pr = parseLlmResponse(text);
  if (!pr) {
    return { skipped: true, reason: 'LLM response could not be parsed as the expected JSON schema', raw_text: text };
  }

  log.info({
    event: 'llm.pr_generated',
    ksi: opts.evidence.ksi_id,
    rule: opts.finding.rule,
    file_count: pr.files.length,
    mechanism: pr.mechanism,
  });

  return { skipped: false, pr };
}

/**
 * Generate PRs for every failing finding in an evidence file. Sequential to
 * keep API rate-limit pressure manageable; the caller can add p-limit if
 * desired.
 */
export async function generatePrsForEvidence(ev: EvidenceFile, opts: Omit<GenerateOptions, 'finding' | 'evidence'> = {}): Promise<Array<{ rule: string; result: GenerateResult }>> {
  const out: Array<{ rule: string; result: GenerateResult }> = [];
  for (const p of ev.providers) {
    for (const f of p.findings) {
      if (f.passed) continue;
      const result = await generatePrForFinding({ ...opts, finding: f, evidence: ev });
      out.push({ rule: f.rule, result });
    }
  }
  return out;
}
