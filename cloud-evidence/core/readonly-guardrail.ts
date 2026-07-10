/**
 * Read-only enforcement.
 *
 * The collector MUST NOT mutate cloud state. We enforce this two ways:
 *
 *   1. We only ever import and call SDK operations whose names match a
 *      read-only verb pattern (Get*, List*, Describe*, BatchGet*, Search*,
 *      Generate*Report, GetCallerIdentity, etc.).
 *   2. We wrap every AWS SDK client with a Proxy that intercepts `.send()`
 *      and inspects the constructor name of the Command being dispatched.
 *      If the constructor's verb is not on the allow-list, we throw before
 *      the call leaves the process.
 *
 * For GCP (googleapis omnibus + @google-cloud/* clients), the API surface
 * is too varied for a single Proxy. We instead enforce by convention in
 * code (only `.get`, `.list`, `.search`, `.export*Assets`, `.recommend*`
 * calls are used) AND by mandating viewer-only IAM roles for the
 * principal (see README).
 */

const READ_ONLY_VERBS = [
  'Get',          // GetUser, GetPolicy, ...
  'List',         // ListUsers, ListPolicies, ...
  'Describe',     // DescribeOrganization, ...
  'BatchGet',     // BatchGetProjects, ...
  'Search',       // SearchUsers, ...
  'Generate',     // GenerateCredentialReport, GenerateServiceLastAccessedDetails (the
                  // *Report family are read-side: they kick off a server-side report
                  // generation that you subsequently GET — the AWS side classifies
                  // them as part of ReadOnlyAccess).
  'Simulate',     // SimulatePrincipalPolicy (read-only "what-if")
  'Lookup',       // LookupEvents (CloudTrail) — read history
  'Check',        // CheckIfPhoneNumberIsOptedOut (rare; included for symmetry)
  'View',         // ViewBilling etc., if ever needed
] as const;

/**
 * Some specific exceptions deserve a special-case allow: their names start
 * with a non-listed verb but they are documented read-only operations.
 */
const READ_ONLY_EXACT_ALLOW = new Set<string>([
  'AssumeRole',                    // STS — produces session credentials, doesn't mutate state we audit
  'AssumeRoleWithSAML',
  'AssumeRoleWithWebIdentity',
  'DecodeAuthorizationMessage',
  // `Select*` reads are documented read-only queries, but the verb "Select" is
  // not one of the READ_ONLY_VERBS prefixes, so they would otherwise fall
  // through to "blocked". These are pure server-side SELECT queries — no
  // mutation — and are part of AWS ReadOnlyAccess:
  'SelectResourceConfig',          // config: SQL over Config-recorded resources (the inventory backbone)
  'SelectAggregateResourceConfig', // config: same, across an aggregator
  'SelectObjectContent',           // s3: S3 Select — reads object content, never writes
]);

/**
 * Verbs that are explicitly disallowed — to be defensive even if matching
 * a permissive prefix accidentally.
 */
const FORBIDDEN_VERB_PREFIXES = [
  'Put','Post','Create','Update','Modify','Set','Delete','Remove','Attach',
  'Detach','Add','Disable','Enable','Restore','Reset','Tag','Untag','Apply',
  'Cancel','Reboot','Start','Stop','Terminate','Send','Sign','Encrypt',
  'Decrypt','Promote','Reject','Approve','Move','Renew','Revoke','Issue',
];

function isReadOnlyOperationName(name: string): boolean {
  if (READ_ONLY_EXACT_ALLOW.has(name)) return true;
  for (const v of FORBIDDEN_VERB_PREFIXES) {
    if (name.startsWith(v)) return false;
  }
  for (const v of READ_ONLY_VERBS) {
    if (name.startsWith(v)) return true;
  }
  return false;
}

export class ReadOnlyViolationError extends Error {
  constructor(operation: string, clientName: string) {
    super(
      `Read-only guardrail blocked operation "${operation}" on client "${clientName}". ` +
      `This collector must never mutate cloud state.`,
    );
    this.name = 'ReadOnlyViolationError';
  }
}

import { withRetry } from './retry.ts';
import { log } from './log.ts';

/** Tunables — overridable via env to make tests deterministic. */
const RETRY_ENABLED = process.env.CLOUD_EVIDENCE_DISABLE_RETRY !== '1';
const RETRY_ATTEMPTS = Number(process.env.CLOUD_EVIDENCE_RETRY_ATTEMPTS ?? 4);
const RETRY_BASE_MS = Number(process.env.CLOUD_EVIDENCE_RETRY_BASE_MS ?? 200);
const RETRY_MAX_MS = Number(process.env.CLOUD_EVIDENCE_RETRY_MAX_MS ?? 5000);

/**
 * Wrap an AWS SDK v3 client so every Command it dispatches is checked.
 * Returns a Proxy that forwards everything except .send(), which we
 * intercept to:
 *   1. validate the Command constructor's verb (read-only enforcement),
 *   2. retry transient failures with decorrelated jitter backoff.
 */
export function wrapAwsClient<T extends { send: (cmd: any) => Promise<any>; constructor: { name: string } }>(
  client: T,
): T {
  return new Proxy(client, {
    get(target, prop, recv) {
      if (prop !== 'send') return Reflect.get(target, prop, recv);
      const original = target.send.bind(target);
      return async function guardedSend(command: any) {
        const commandName: string = command?.constructor?.name ?? '<unknown>';
        const opName = commandName.endsWith('Command') ? commandName.slice(0, -'Command'.length) : commandName;
        if (!isReadOnlyOperationName(opName)) {
          throw new ReadOnlyViolationError(opName, target.constructor.name);
        }
        if (!RETRY_ENABLED) return original(command);
        return withRetry(() => original(command), {
          attempts: RETRY_ATTEMPTS,
          baseDelayMs: RETRY_BASE_MS,
          maxDelayMs: RETRY_MAX_MS,
          onRetry: (attempt, err, delayMs) => {
            log.warn({
              event: 'sdk.retry',
              client: target.constructor.name,
              op: opName,
              attempt,
              delay_ms: delayMs,
              err_name: (err as any)?.name,
              err_message: (err as any)?.message,
              http_status: (err as any)?.$metadata?.httpStatusCode,
            });
          },
        });
      };
    },
  });
}

/** Exposed for unit-testing the allowlist outside SDK context. */
export const _internal = { isReadOnlyOperationName };
