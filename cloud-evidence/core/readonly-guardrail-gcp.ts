/**
 * GCP read-only guardrail.
 *
 * Companion to core/readonly-guardrail.ts (which handles AWS SDK v3 Commands).
 *
 * Why GCP needs its own:
 *   - AWS SDK v3 dispatches via `client.send(command)` where `command` is a
 *     class — we can introspect the constructor name uniformly across every
 *     service.
 *   - GCP has multiple client styles:
 *       * googleapis omnibus: `client.projects.serviceAccounts.list({...})`
 *       * @google-cloud/* per-service: `new ComputeClient(); await client.listInstances({...})`
 *       * grpc clients: `await client.getProject({...})`
 *     Each calls method names directly on the client object — there's no
 *     central "send" we can wrap.
 *
 * What this module does:
 *   - Wraps a GCP client (any object) in a Proxy that, on every method call,
 *     checks the method name against an allowlist (get*, list*, search*,
 *     export*, recommend*, …) and a denylist (create*, update*, delete*,
 *     patch*, set*, insert*, …).
 *   - Recurses into property accesses so nested call chains
 *     (`client.projects.serviceAccounts.list(...)`) are all guarded.
 *   - Logs every blocked call and throws.
 *
 * Limitations:
 *   - We can't see into internal helper modules — only what's invoked via
 *     the wrapper. Collectors must use `wrapGcpClient()` consistently.
 *   - The deny pattern is *prefix-based*; if a future GCP API names a
 *     read-only method "deleteSnapshot" (no such thing today, but) it
 *     would be incorrectly blocked. We can override per-call with the
 *     `READ_ONLY_GCP_EXCEPTIONS` set.
 *
 * As with AWS, this is a DEFENSE IN DEPTH measure — the principal MUST also
 * be limited to read-only roles via IAM (see README).
 */
import { log } from './log.ts';

const READ_VERB_PREFIXES = [
  'get', 'list', 'search', 'aggregated', 'aggregate',
  'export', 'exportAssets',
  'recommend', 'recommendation',
  'fetch', 'describe', 'lookup', 'query', 'check', 'preview', 'test', 'simulate', 'analyze',
  'count', 'view',
  // Iterator factories produced by @google-cloud/* clients
  'createListStream',          // Async iterator over results — read-only despite the "create" verb
  'getIamPolicy',              // Read-side IAM
  'testIamPermissions',        // Read-only "what can I do?"
];

const WRITE_VERB_PREFIXES = [
  'create', 'update', 'patch', 'delete', 'remove',
  'set', 'insert', 'add', 'append',
  'enable', 'disable', 'undelete', 'restore',
  'attach', 'detach',
  'cancel', 'stop', 'start', 'resume', 'pause', 'reset',
  'move', 'transfer',
  'tag', 'untag', 'label', 'unlabel',
  'replaceAll', 'replace',
  'apply', 'promote', 'rollback',
  'sign', 'encrypt', 'decrypt',
  'send', 'post', 'put',
  'grant', 'revoke',
  'execute', 'invoke', 'run',
  'commit',
];

/** Methods that are NOT prefix-classifiable. Override decisions here (read-only allowlist). */
const READ_ONLY_GCP_EXCEPTIONS = new Set<string>([
  'auth', 'authorize',
  'close',                  // releases gRPC connection — local-only, safe
  'request',                // generic HTTP request — caller is responsible
  'toString', 'inspect',    // util methods used in debug
  'on', 'once', 'off', 'removeListener', 'removeAllListeners', 'emit',
  'pipe', 'unpipe',
  'then', 'catch', 'finally', // Promise interop — wrapping doesn't make a real call
  // Method names that LOOK mutating but are documented read-only in GCP SDKs:
  'createListStream',       // @google-cloud/* AsyncIterable factory
  'createReadStream',       // GCS reader
]);

export class ReadOnlyGcpViolationError extends Error {
  constructor(method: string, path: string[]) {
    super(`GCP read-only guardrail blocked method "${path.concat(method).join('.')}". This collector must never mutate cloud state.`);
    this.name = 'ReadOnlyGcpViolationError';
  }
}

function isCamelBoundary(s: string, idx: number): boolean {
  if (idx >= s.length) return true; // exact verb match — treat as boundary
  const ch = s.charAt(idx);
  // Camel boundary if uppercase letter, or digit, or non-letter (start of new token)
  return ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9';
}

function classify(name: string): 'read' | 'write' | 'unknown' {
  // Read-only exceptions FIRST so a method like `createListStream` is allowed
  // even though it starts with the "create" write prefix.
  if (READ_ONLY_GCP_EXCEPTIONS.has(name)) return 'read';
  // Symbol/private/internal methods passthrough
  if (typeof name !== 'string' || name.startsWith('_') || name.startsWith('@@')) return 'read';
  for (const w of WRITE_VERB_PREFIXES) {
    if (name === w || name.startsWith(w) && isCamelBoundary(name, w.length)) return 'write';
  }
  for (const r of READ_VERB_PREFIXES) {
    if (name === r || name.startsWith(r) && isCamelBoundary(name, r.length)) return 'read';
    // Some read verbs naturally take noun-style suffixes that aren't camel-cased
    // (e.g. "recommendations" — the "s" is part of the same word). Allow if the
    // remainder is alphanumeric and the verb is in this short list of nouny verbs.
    if (['recommend', 'list', 'search', 'export', 'fetch', 'query', 'check'].includes(r) &&
        name.startsWith(r) && /^[a-z0-9]*$/.test(name.slice(r.length))) {
      return 'read';
    }
  }
  return 'unknown';
}

/**
 * Wrap a GCP client object in a recursive Proxy. Method calls whose name
 * doesn't classify as a read operation throw `ReadOnlyGcpViolationError`.
 *
 * Pass an optional `clientName` for clearer error messages and structured
 * logging.
 */
export function wrapGcpClient<T extends object>(client: T, clientName = 'gcp-client'): T {
  return wrap(client, [clientName]) as T;
}

function wrap(target: any, path: string[]): any {
  if (target === null || typeof target !== 'object' && typeof target !== 'function') return target;

  return new Proxy(target, {
    get(t, prop, recv) {
      const value = Reflect.get(t, prop, recv);
      if (typeof prop === 'symbol') return value;
      const name = String(prop);

      // Pass plain data through
      if (value === null || (typeof value !== 'function' && typeof value !== 'object')) return value;

      // If it's a function, wrap to classify on call
      if (typeof value === 'function') {
        const fn = value.bind(t);
        return function guarded(...args: any[]) {
          const verdict = classify(name);
          if (verdict === 'write') {
            log.error({ event: 'gcp.readonly_block', client: path[0], method: name, path: path.concat(name).join('.') });
            throw new ReadOnlyGcpViolationError(name, path);
          }
          const out = fn(...args);
          // If the call returns a Promise, return as-is.
          // If it returns an object (sub-client), wrap it too.
          if (out && typeof out === 'object' && typeof out.then !== 'function') {
            return wrap(out, path.concat(name));
          }
          return out;
        };
      }

      // It's an object (sub-namespace). Recurse.
      return wrap(value, path.concat(name));
    },
  });
}

/** Exposed for tests. */
export const _internal = { classify };
