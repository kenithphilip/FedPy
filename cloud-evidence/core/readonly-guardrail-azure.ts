/**
 * Azure read-only guardrail.
 *
 * Companion to core/readonly-guardrail.ts (AWS) and core/readonly-guardrail-gcp.ts
 * (GCP). The Azure SDK looks more like GCP than AWS:
 *   - There's no central `client.send(command)`; each ARM client exposes
 *     method-chain APIs like `subscriptionClient.subscriptions.list()` or
 *     `resourceClient.resources.listByResourceGroup(...)`.
 *   - Long-running operations use a `begin*` prefix family (`beginCreate`,
 *     `beginCreateOrUpdate`, `beginDeleteAndWait`, …) that returns a poller.
 *     These are unambiguously writes.
 *
 * What this module does:
 *   - Wraps any Azure SDK client (any object) in a Proxy that, on every method
 *     call, checks the method name against an allowlist (get*, list*, check*,
 *     describe*, query*, page*, …) and a denylist (create*, update*, delete*,
 *     patch*, set*, begin*, …).
 *   - Recurses into property accesses so nested call chains
 *     (`client.subscriptions.list(...)`) are all guarded.
 *   - Logs every blocked call and throws.
 *
 * As with AWS and GCP, this is DEFENSE IN DEPTH — the runner's principal MUST
 * also be limited to read-only roles in Azure RBAC (Reader + Security Reader +
 * Log Analytics Reader; see IAM-PERMISSIONS-CATALOG.md).
 */
import { log } from './log.ts';

const READ_VERB_PREFIXES = [
  'get', 'list', 'search',
  'check', 'describe', 'fetch', 'lookup', 'query', 'analyze',
  'count', 'view', 'preview', 'test', 'simulate',
  // Azure SDK PagedAsyncIterableIterator surface
  'page', 'byPage', 'next', 'iterator',
  'export', 'download',
];

const WRITE_VERB_PREFIXES = [
  'create', 'update', 'patch', 'delete', 'remove',
  'set', 'insert', 'add', 'append',
  'enable', 'disable', 'undelete', 'restore',
  'attach', 'detach',
  'stop', 'start', 'resume', 'pause', 'reset', 'restart', 'redeploy', 'reboot',
  'move', 'transfer',
  'tag', 'untag', 'label', 'unlabel',
  'replaceAll', 'replace',
  'apply', 'promote', 'rollback', 'failover',
  'sign', 'encrypt', 'decrypt', 'wrap', 'unwrap',
  'post', 'put',
  'grant', 'revoke',
  'execute', 'invoke', 'run', 'trigger',
  'commit', 'publish', 'install', 'uninstall', 'upgrade', 'rotate',
  // Azure long-running operation prefix family — beginCreate/beginDelete/beginUpdate/…
  'begin',
  // Azure rotation/regeneration patterns
  'regenerate', 'renew',
];

/** Methods that are NOT prefix-classifiable. Override decisions here (read-only allowlist). */
const READ_ONLY_AZURE_EXCEPTIONS = new Set<string>([
  'auth', 'authorize',
  'close',                  // releases connection — local, safe
  'request', 'sendRequest', // generic HTTP — internal Azure SDK plumbing, not a user write
  'toString', 'inspect',
  'on', 'once', 'off', 'removeListener', 'removeAllListeners', 'emit',
  'pipe', 'unpipe',
  'then', 'catch', 'finally',
  'pipeline',               // SDK request-pipeline accessor
  'sdkRuntime',
]);

export class ReadOnlyAzureViolationError extends Error {
  constructor(method: string, path: string[]) {
    super(`Azure read-only guardrail blocked method "${path.concat(method).join('.')}". This collector must never mutate cloud state.`);
    this.name = 'ReadOnlyAzureViolationError';
  }
}

function isCamelBoundary(s: string, idx: number): boolean {
  if (idx >= s.length) return true;
  const ch = s.charAt(idx);
  return ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9';
}

function classify(name: string): 'read' | 'write' | 'unknown' {
  if (READ_ONLY_AZURE_EXCEPTIONS.has(name)) return 'read';
  if (typeof name !== 'string' || name.startsWith('_') || name.startsWith('@@')) return 'read';
  for (const w of WRITE_VERB_PREFIXES) {
    if (name === w || name.startsWith(w) && isCamelBoundary(name, w.length)) return 'write';
  }
  for (const r of READ_VERB_PREFIXES) {
    if (name === r || name.startsWith(r) && isCamelBoundary(name, r.length)) return 'read';
    // Read verbs with nouny suffixes (e.g. "lists", "checks") — only on a short list.
    if (['list', 'search', 'export', 'fetch', 'query', 'check'].includes(r) &&
        name.startsWith(r) && /^[a-z0-9]*$/.test(name.slice(r.length))) {
      return 'read';
    }
  }
  return 'unknown';
}

/**
 * Wrap an Azure SDK client in a recursive Proxy. Method calls whose name
 * doesn't classify as a read operation throw `ReadOnlyAzureViolationError`.
 */
export function wrapAzureClient<T extends object>(client: T, clientName = 'azure-client'): T {
  return wrap(client, [clientName]) as T;
}

function wrap(target: any, path: string[]): any {
  if (target === null || typeof target !== 'object' && typeof target !== 'function') return target;

  return new Proxy(target, {
    get(t, prop, recv) {
      const value = Reflect.get(t, prop, recv);
      if (typeof prop === 'symbol') return value;
      const name = String(prop);

      if (value === null || (typeof value !== 'function' && typeof value !== 'object')) return value;

      if (typeof value === 'function') {
        const fn = value.bind(t);
        return function guarded(...args: any[]) {
          const verdict = classify(name);
          if (verdict === 'write') {
            log.error({ event: 'azure.readonly_block', client: path[0], method: name, path: path.concat(name).join('.') });
            throw new ReadOnlyAzureViolationError(name, path);
          }
          const out = fn(...args);
          if (out && typeof out === 'object' && typeof out.then !== 'function') {
            return wrap(out, path.concat(name));
          }
          return out;
        };
      }

      return wrap(value, path.concat(name));
    },
  });
}

/** Exposed for tests. */
export const _internal = { classify };
