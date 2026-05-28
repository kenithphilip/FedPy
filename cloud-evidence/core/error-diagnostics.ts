/**
 * Operator-facing error diagnostic helpers.
 *
 * Goal: turn an opaque AWS / GCP / K8s SDK error into a one-line warning that
 * tells the operator EXACTLY what permission to grant (or what other action
 * to take). The audit found multiple collectors that wrote `warnings.push(
 * "ListXxx: " + e.message)` and left the reader to grep AWS docs for the
 * action name. This module centralizes that translation.
 *
 * Usage in collectors:
 *
 *   try {
 *     const out = await client.send(new ListUsersCommand({}));
 *   } catch (e) {
 *     warnings.push(diagnoseAwsError(e, 'iam.ListUsers', 'iam:ListUsers'));
 *   }
 *
 * The function returns a string. If the error is a permission-denied
 * variant, the string includes the action name and a hint about which IAM
 * policy/role to attach. Otherwise the original message is preserved with
 * the source label prefix.
 *
 * The helper does NOT throw — it always returns a string. Safe to call on
 * any input.
 */

export interface ErrorContext {
  /** SDK call name for the operator (e.g. "iam.ListUsers", "compute.list"). */
  source: string;
  /** The IAM/GCP-role/K8s-verb the runner needs to grant. */
  required: string;
  /** Optional extra hint shown on access-denied. */
  hint?: string;
}

const AWS_ACCESS_DENIED_NAMES = new Set([
  'AccessDenied',
  'AccessDeniedException',
  'UnauthorizedException',
  'NotAuthorized',
  'NotAuthorizedException',
  'ForbiddenException',
  'AuthFailure',
  'AuthorizationError',
  'InvalidAccessKeyId',
  'SignatureDoesNotMatch',
  'TokenRefreshRequired',
]);

const AWS_THROTTLING_NAMES = new Set([
  'Throttling',
  'ThrottlingException',
  'RequestLimitExceeded',
  'TooManyRequestsException',
  'ProvisionedThroughputExceededException',
]);

const AWS_NOT_FOUND_NAMES = new Set([
  'NoSuchEntity',
  'NoSuchEntityException',
  'ResourceNotFoundException',
  'NotFoundException',
  'ResourceNotFound',
  'NoSuchBucket',
  'NoSuchKey',
  'NoSuchTrail',
]);

const AWS_NOT_ENABLED_NAMES = new Set([
  'OptInRequired',
  'SubscriptionRequiredException',
  'OrganizationsNotInUseException',
  'AWSOrganizationsNotInUseException',
  'EnableException',
]);

/**
 * Classify an error into one of these buckets so collectors can decide
 * whether to record it as a hard warning, a soft note, or skip it.
 */
export type ErrorClass =
  | 'access_denied'        // Operator must grant a permission.
  | 'throttling'           // Transient; retry layer should have caught it.
  | 'not_found'            // Resource genuinely doesn't exist; usually expected.
  | 'not_enabled'          // Service not enabled in this account/region; expected.
  | 'network'              // Connection failure, DNS, timeout.
  | 'malformed_response'   // The SDK got JSON it couldn't parse.
  | 'unknown';

export function classifyError(err: unknown): ErrorClass {
  if (!err || typeof err !== 'object') return 'unknown';
  const e = err as any;
  const name = String(e.name ?? '');
  const code = String(e.code ?? '');
  const statusCode = e?.$metadata?.httpStatusCode ?? e?.statusCode;
  const msg = String(e.message ?? '').toLowerCase();

  if (AWS_ACCESS_DENIED_NAMES.has(name) || AWS_ACCESS_DENIED_NAMES.has(code)) return 'access_denied';
  if (statusCode === 403) return 'access_denied';
  if (msg.includes('access denied') || msg.includes('not authorized to perform') || msg.includes('permission denied')) return 'access_denied';

  if (AWS_THROTTLING_NAMES.has(name) || AWS_THROTTLING_NAMES.has(code)) return 'throttling';
  if (statusCode === 429) return 'throttling';

  if (AWS_NOT_FOUND_NAMES.has(name) || AWS_NOT_FOUND_NAMES.has(code)) return 'not_found';
  if (statusCode === 404) return 'not_found';

  if (AWS_NOT_ENABLED_NAMES.has(name) || AWS_NOT_ENABLED_NAMES.has(code)) return 'not_enabled';

  if (['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH'].includes(code)) return 'network';
  if (name === 'TimeoutError' || name === 'NetworkingError') return 'network';

  if (name === 'SyntaxError' || msg.includes('unexpected token') || msg.includes('json')) return 'malformed_response';

  return 'unknown';
}

/**
 * Produce a human-actionable warning string from an SDK error.
 *
 * AccessDenied:
 *   "iam.ListUsers AccessDenied — grant iam:ListUsers to the runner role (current message: ...)"
 *
 * NotFound (expected for many calls — e.g. GetLoginProfile for a user without one):
 *   "iam.GetLoginProfile NotFound — user has no console login (expected for service users)"
 *
 * Throttling (should normally be retried; if reached the catch, retry exhausted):
 *   "iam.ListUsers throttled — retry budget exhausted; raise CLOUD_EVIDENCE_RETRY_ATTEMPTS or run during off-peak"
 *
 * Network:
 *   "iam.ListUsers ENOTFOUND iam.us-east-1.amazonaws.com — check DNS / VPC endpoints"
 *
 * Unknown:
 *   "iam.ListUsers: <original message>"  (fallback)
 */
export function diagnoseAwsError(err: unknown, source: string, requiredAction: string, hint?: string): string {
  const e = err as any;
  const klass = classifyError(err);
  const baseMsg = (e?.message ?? String(err)).slice(0, 300);

  switch (klass) {
    case 'access_denied':
      return `${source} AccessDenied — grant ${requiredAction} to the runner IAM role${hint ? ' (' + hint + ')' : ''}. Underlying: ${baseMsg}`;
    case 'throttling':
      return `${source} throttled — retry budget exhausted; raise CLOUD_EVIDENCE_RETRY_ATTEMPTS or schedule the run during off-peak hours. Underlying: ${baseMsg}`;
    case 'not_found':
      return `${source} NotFound (often expected — resource doesn't exist). Underlying: ${baseMsg}`;
    case 'not_enabled':
      return `${source} service not enabled in this account/region. Enable the service or scope the collector to regions where it is. Underlying: ${baseMsg}`;
    case 'network':
      return `${source} network error (${e?.code ?? 'unknown'}) — check VPC endpoints, DNS, proxy. Underlying: ${baseMsg}`;
    case 'malformed_response':
      return `${source} malformed response — SDK could not parse JSON. May indicate a transient API issue. Underlying: ${baseMsg}`;
    default:
      return `${source}: ${baseMsg}`;
  }
}

/**
 * Same diagnostic envelope, scoped to GCP error shapes (grpc status code +
 * .details). We map the gRPC codes to the same classes above.
 */
export function diagnoseGcpError(err: unknown, source: string, requiredRoleOrPermission: string): string {
  const e = err as any;
  const grpcCode = typeof e?.code === 'number' ? e.code : (typeof e?.status?.code === 'number' ? e.status.code : null);
  const baseMsg = (e?.message ?? String(err)).slice(0, 300);

  // gRPC code 7 = PERMISSION_DENIED, 16 = UNAUTHENTICATED
  if (grpcCode === 7) {
    return `${source} PERMISSION_DENIED — grant ${requiredRoleOrPermission} to the runner principal. Underlying: ${baseMsg}`;
  }
  if (grpcCode === 16) {
    return `${source} UNAUTHENTICATED — ADC may be expired; run 'gcloud auth application-default login'. Underlying: ${baseMsg}`;
  }
  // gRPC code 5 = NOT_FOUND
  if (grpcCode === 5) {
    return `${source} NOT_FOUND (resource doesn't exist). Underlying: ${baseMsg}`;
  }
  // gRPC code 8 = RESOURCE_EXHAUSTED → quota
  if (grpcCode === 8) {
    return `${source} RESOURCE_EXHAUSTED — quota/throttle. Underlying: ${baseMsg}`;
  }
  // HTTP-style 403/404
  if (e?.code === 403 || /permission denied/i.test(baseMsg)) {
    return `${source} 403 PermissionDenied — grant ${requiredRoleOrPermission} to the runner principal. Underlying: ${baseMsg}`;
  }
  if (e?.code === 404) {
    return `${source} 404 NotFound (resource doesn't exist). Underlying: ${baseMsg}`;
  }
  return `${source}: ${baseMsg}`;
}

/**
 * Same shape for Kubernetes errors. The K8s client returns errors with
 * `.statusCode` from the underlying HTTP request, and the body often contains
 * a JSON message like `{ "kind": "Status", "code": 403, "message": "..." }`.
 */
export function diagnoseK8sError(err: unknown, source: string, rbacVerb: string, resource: string): string {
  const e = err as any;
  const statusCode = e?.statusCode ?? e?.response?.statusCode;
  const baseMsg = (e?.message ?? e?.response?.body?.message ?? String(err)).slice(0, 300);

  if (statusCode === 403 || /forbidden/i.test(baseMsg)) {
    return `${source} 403 Forbidden — bind the runner ServiceAccount to a ClusterRole granting [${rbacVerb}] on ${resource}. Underlying: ${baseMsg}`;
  }
  if (statusCode === 401 || /unauthorized/i.test(baseMsg)) {
    return `${source} 401 Unauthorized — kubeconfig may be expired. Re-run 'aws eks update-kubeconfig' / 'gcloud container clusters get-credentials'. Underlying: ${baseMsg}`;
  }
  if (statusCode === 404) {
    return `${source} 404 NotFound — resource doesn't exist (often expected). Underlying: ${baseMsg}`;
  }
  if (e?.code === 'ECONNREFUSED' || e?.code === 'ETIMEDOUT' || /timeout|unreachable/i.test(baseMsg)) {
    return `${source} cluster unreachable — check kubeconfig server URL + network connectivity. Underlying: ${baseMsg}`;
  }
  return `${source}: ${baseMsg}`;
}
