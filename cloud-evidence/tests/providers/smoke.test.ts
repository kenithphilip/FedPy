/**
 * Provider collector smoke test — runs every registered AWS and GCP collector
 * against a degraded-mode fake SDK and asserts:
 *   1. The collector does not throw.
 *   2. The returned ProviderBlock has the right `provider` field.
 *   3. Every emitted Finding survives schema validation.
 *
 * This is the safety net for the 26 collector modules that don't have
 * dedicated unit tests (only IAM-MFA + K8s-IAM-ELP do). It won't catch logic
 * bugs in branch coverage — the empty SDK responses route through the
 * fail-open path of most collectors. It WILL catch:
 *   - Runtime crashes on no-data input
 *   - Missing required v3 fields (current_state.summary, target_state.rationale, etc.)
 *   - Provider field mismatch (e.g. AWS collector returning provider:'gcp')
 *   - Severity / mechanism values that aren't in the enum
 *
 * GCP collectors are stubbed via the fake googleClient that returns empty
 * arrays for every list call. K8s uses the same kubeconfig stub pattern as
 * tests/providers/k8s/security.test.ts.
 */
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { setFakeResponses } from '../helpers/fake-aws-sdk.ts';
import { validateEvidenceFile } from '../../core/schema.ts';
import type { ProviderBlock, EvidenceFile, Finding } from '../../core/envelope.ts';
import type { KsiEntry } from '../../core/ksi-map.ts';

// Mock all three auth modules so collectors run without real credentials.
vi.mock('../../core/auth/aws.ts', () => import('../helpers/fake-aws-sdk.ts'));

vi.mock('../../core/auth/gcp.ts', () => ({
  whoAmIGcp: async () => ({ principal: 'test@example.com' }),
  googleClient: async () => makeGcpStub(),
  guardGcp: (x: any) => x,
}));

// Azure Microsoft Graph stub: every Graph fetch returns an empty list / null body,
// so collectors exercise their no-data path without network or auth.
vi.mock('../../core/auth/azure-graph.ts', () => ({
  graphFetchAll: async () => ({ items: [], warnings: [] }),
  graphFetchOne: async () => ({ data: null, warnings: [] }),
  _resetTokenCache: () => { /* noop */ },
}));

// Azure ARM stubs (DefaultAzureCredential / Resource Graph). Without this the
// real azure.resourceGraph() constructs a DefaultAzureCredential chain probe
// that hangs for ~30s+ in CI (no Azure creds present) and the smoke test times
// out. We return a Resource Graph client whose `resources()` call yields an
// empty page — collectors exercise their no-data path.
vi.mock('../../core/auth/azure.ts', () => ({
  whoAmIAzure: async () => ({ principal: 'smoke', tenantId: 'smoke-tenant', appId: null }),
  guardAzure: <T extends object>(c: T) => c,
  resourceGraph: () => ({ async resources(_req: any) { return { data: [] }; } }),
  resources: (_id: string) => ({}),
}));

vi.mock('../../core/auth/k8s.ts', () => ({
  makeK8sAuth: () => ({
    context: 'smoke',
    server: 'https://k8s.smoke.local',
    core: makeK8sApiStub(),
    rbac: makeK8sApiStub(),
    network: makeK8sApiStub(),
    apps: makeK8sApiStub(),
    apiextensions: makeK8sApiStub(),
  }),
  listK8sContexts: () => [],
  whoAmIK8s: async () => ({ context: 'smoke', server: 'https://k8s.smoke.local', version: 'v1' }),
}));

// ---- GCP stub: returns empty lists for every method call ----
function makeGcpStub(): any {
  const handler: ProxyHandler<any> = {
    get(_target, prop) {
      if (prop === 'then' || prop === 'catch') return undefined;
      if (prop === Symbol.toPrimitive || prop === Symbol.iterator) return undefined;
      if (typeof prop === 'symbol') return undefined;
      // Return another proxy so chained accesses keep working
      return new Proxy(() => Promise.resolve({ data: {} }), handler);
    },
    apply(_target, _this, _args) {
      return Promise.resolve({ data: {} });
    },
  };
  return new Proxy(() => Promise.resolve({ data: {} }), handler);
}

// ---- K8s API stub ----
function makeK8sApiStub(): any {
  return new Proxy({}, {
    get() {
      // All methods return { items: [] } — enough for the smoke test
      return async () => ({ items: [] });
    },
  });
}

// ---- Tests ----

function validateBlock(block: ProviderBlock, ksiId: string, provider: 'aws' | 'gcp' | 'azure' | 'k8s'): void {
  expect(block.provider).toBe(provider);
  // Wrap in a minimal EvidenceFile so we can reuse validateEvidenceFile
  const envelope: EvidenceFile = {
    ksi_id: ksiId,
    ksi_name: ksiId,
    ksi_statement: 'smoke',
    scope: 'CLOUD',
    frmr_version: 'smoke',
    run_id: '00000000-0000-0000-0000-000000000000',
    collected_at: '2026-05-28T00:00:00.000Z',
    providers: [block],
    rollup: {
      pass: block.findings.every((f: Finding) => f.passed),
      passing_findings: block.findings.filter((f) => f.passed).length,
      failing_findings: block.findings.filter((f) => !f.passed).length,
      warnings: block.warnings ?? [],
      missing_evidence: [],
      alternatives_in_play: 0,
    },
  };
  const serialized = JSON.parse(JSON.stringify(envelope));
  const r = validateEvidenceFile(serialized);
  if (!r.valid) {
    // Surface the first ajv error for easier debugging
    const first = r.errors[0];
    throw new Error(`Schema invalid for ${ksiId}/${provider}: ${first?.instancePath} ${first?.message}`);
  }
}

let supportedKsis: string[] = [];
let ksiMap: Record<string, KsiEntry> = {};

beforeAll(async () => {
  setFakeResponses({});  // every fake call returns {}
  // Late-import so the vi.mock above wires through before ksi-map is evaluated.
  const m = await import('../../core/ksi-map.ts');
  supportedKsis = m.SUPPORTED_KSIS;
  ksiMap = m.KSI_MAP;
});

describe('Provider smoke test — AWS collectors', () => {
  it('SUPPORTED_KSIS has at least one entry', () => {
    expect(supportedKsis.length).toBeGreaterThan(0);
  });

  it('every AWS collector returns a schema-valid ProviderBlock with provider=aws', async () => {
    const failures: string[] = [];
    for (const ksiId of supportedKsis) {
      const ksi = ksiMap[ksiId];
      if (!ksi?.aws) continue;
      try {
        const block = await ksi.aws({ aws: { account_id: '111122223333', region: 'us-east-1' } });
        validateBlock(block, ksiId, 'aws');
      } catch (e: any) {
        failures.push(`${ksiId}: ${e.message}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`AWS collector smoke failures (${failures.length}):\n${failures.join('\n')}`);
    }
  }, 30_000);
});

describe('Provider smoke test — GCP collectors', () => {
  it('every GCP collector returns a schema-valid ProviderBlock with provider=gcp', async () => {
    const failures: string[] = [];
    for (const ksiId of supportedKsis) {
      const ksi = ksiMap[ksiId];
      if (!ksi?.gcp) continue;
      try {
        const block = await ksi.gcp({ gcp: { project_id: 'smoke-project' } });
        validateBlock(block, ksiId, 'gcp');
      } catch (e: any) {
        failures.push(`${ksiId}: ${e.message}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`GCP collector smoke failures (${failures.length}):\n${failures.join('\n')}`);
    }
  }, 30_000);
});

describe('Provider smoke test — Azure collectors', () => {
  it('every Azure collector returns a schema-valid ProviderBlock with provider=azure', async () => {
    const failures: string[] = [];
    for (const ksiId of supportedKsis) {
      const ksi = ksiMap[ksiId];
      if (!ksi?.azure) continue;
      try {
        const block = await ksi.azure({ azure: { tenant_id: 'smoke-tenant', subscription_id: 'smoke-sub' } });
        validateBlock(block, ksiId, 'azure');
      } catch (e: any) {
        failures.push(`${ksiId}: ${e.message}`);
      }
    }
    if (failures.length > 0) {
      throw new Error(`Azure collector smoke failures (${failures.length}):\n${failures.join('\n')}`);
    }
  }, 30_000);
});
