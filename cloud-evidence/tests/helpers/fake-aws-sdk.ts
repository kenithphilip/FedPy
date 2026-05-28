/**
 * Test helper: a drop-in replacement for `core/auth/aws.ts`.
 *
 * Instead of returning real AWS SDK clients, every client factory returns
 * a `FakeAwsClient` whose `.send(command)` replays canned responses from
 * a fixture object keyed by command name (e.g. "ListUsers").
 *
 * Per-test setup:
 *   setFakeResponses(iamMfaPassing);
 *
 * Then in the test file:
 *   vi.mock('../../../core/auth/aws.ts', () => import('../../helpers/fake-aws-sdk.ts'));
 *   beforeEach(() => setFakeResponses(myFixture));
 *
 * The fake client also tracks every command name dispatched so tests can assert
 * "collector called X but not Y" — useful for verifying read-only behavior.
 */
import type { CollectorContext } from '../../core/ksi-map.ts';

/**
 * Each value is either:
 *   - a static object that's cloned and returned verbatim, or
 *   - a function `(input) => response` that inspects the Command's input
 *     (e.g. to differentiate `ListMFADevices({ UserName: 'alice' })` vs
 *     `ListMFADevices({ UserName: 'bob' })`).
 */
export type FakeResponse = unknown | ((input: any) => unknown);
export type FakeResponses = Record<string, FakeResponse>;

let currentResponses: FakeResponses = {};
const callLog: string[] = [];

/** Set the canned responses the next collector run will see. */
export function setFakeResponses(r: FakeResponses): void {
  currentResponses = r;
  callLog.length = 0;
}

/** Inspect commands dispatched since the last setFakeResponses(). */
export function getCallLog(): string[] {
  return [...callLog];
}

class FakeAwsClient {
  async send(command: any): Promise<unknown> {
    const name: string = command?.constructor?.name ?? '<unknown>';
    const op = name.endsWith('Command') ? name.slice(0, -'Command'.length) : name;
    const input = command?.input ?? {};
    callLog.push(op);

    // Allow lookups by exact op name, or by "client.op" composite key.
    const direct = currentResponses[op];
    if (direct !== undefined) return resolve(direct, input);

    for (const [k, v] of Object.entries(currentResponses)) {
      if (k.endsWith(`.${op}`) || k === op) return resolve(v, input);
    }

    // Default empty response — many SDK calls return empty lists when nothing matches.
    return {};
  }
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v));
}

function resolve(v: FakeResponse, input: any): unknown {
  if (typeof v === 'function') {
    const out = (v as (i: any) => unknown)(input);
    return out === undefined ? {} : clone(out as any);
  }
  return clone(v as any);
}

const sharedClient = new FakeAwsClient();
const factory = (_a?: unknown) => sharedClient;

// ---- Matches the surface of core/auth/aws.ts ----

export interface AwsAuth {
  region: string;
  credentials: () => unknown;
}

export function makeAwsAuth(region: string): AwsAuth {
  return { region, credentials: () => ({}) };
}

export async function whoAmI(_auth: AwsAuth): Promise<{ account: string; arn: string; userId: string }> {
  return {
    account: '111122223333',
    arn: 'arn:aws:sts::111122223333:assumed-role/test/test-session',
    userId: 'AROATEST:test-session',
  };
}

// Every client factory returns the shared fake client.
export const iam = factory;
export const identitystore = factory;
export const ssoadmin = factory;
export const organizations = factory;
export const accessanalyzer = factory;
export const guardduty = factory;
export const securityhub = factory;
export const eventbridge = factory;
export const lambda = factory;
export const ssm = factory;
export const cognito = factory;
export const ec2 = factory;
export const elbv2 = factory;
export const s3 = factory;
export const rds = factory;
export const eks = factory;
export const cloudfront = factory;
export const wafv2 = factory;
export const shield = factory;
export const networkFirewall = factory;
export const configService = factory;
export const cloudformation = factory;
export const autoScaling = factory;
export const dynamodb = factory;
export const backup = factory;
export const cloudtrail = factory;
export const cloudwatchlogs = factory;
export const athena = factory;
export const firehose = factory;
export const ecr = factory;
export const codepipeline = factory;
export const codebuild = factory;
export const signer = factory;
export const inspector2 = factory;
export const secretsmanager = factory;
export const kms = factory;
export const acm = factory;
export const appmesh = factory;

/** Convenience: build a CollectorContext with default test values. */
export function fakeAwsContext(): CollectorContext {
  return { aws: { account_id: '111122223333', region: 'us-east-1' } };
}
