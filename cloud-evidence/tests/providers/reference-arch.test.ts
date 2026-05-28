/**
 * Reference-architecture audit tests (AWS-CHK / GCP-CHK).
 *
 * Verifies the two FedRAMP reference-architecture collectors:
 *   - providers/aws/reference-arch.ts  → AUDIT-REFARCH-AWS
 *   - providers/gcp/reference-arch.ts  → AUDIT-REFARCH-GCP
 *
 * Both are exercised against fake SDKs (no network). We assert:
 *   1. A fully-hardened environment makes every check pass.
 *   2. A degraded/empty environment never throws and still emits a schema-valid
 *      EvidenceFile (the fail-open contract).
 *   3. GCP org-scoped checks skip-with-warning (not fail) when no org is configured.
 *   4. The emitted file carries the expected ksi_id / scope / provider shape.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setFakeResponses, makeAwsAuth } from '../helpers/fake-aws-sdk.ts';
import { validateEvidenceFile } from '../../core/schema.ts';
import type { EvidenceFile } from '../../core/envelope.ts';

// ---- AWS: swap the real auth module for the fake SDK ----
vi.mock('../../core/auth/aws.ts', () => import('../helpers/fake-aws-sdk.ts'));

// ---- GCP: a path-tracking stub for the googleapis dynamic client ----
// `gcpState.routes` maps "<api>:<dotted.method.path>" → response (or fn(input)).
// Anything unrouted resolves to { data: {} } (the degraded path).
const gcpState = vi.hoisted(() => ({ routes: {} as Record<string, unknown> }));
vi.mock('../../core/auth/gcp.ts', () => {
  function makeGcpClient(api: string): any {
    function make(path: string): any {
      const fn = (input?: any) => {
        const r = gcpState.routes[`${api}:${path}`];
        if (r === undefined) return Promise.resolve({ data: {} });
        return Promise.resolve(typeof r === 'function' ? (r as (i: any) => unknown)(input) : r);
      };
      return new Proxy(fn, {
        get(_t, prop) {
          if (typeof prop === 'symbol' || prop === 'then' || prop === 'catch') return undefined;
          return make(path ? `${path}.${String(prop)}` : String(prop));
        },
        apply(_t, _this, args) { return fn(args[0]); },
      });
    }
    return make('');
  }
  return {
    whoAmIGcp: async () => ({ principal: 'test@example.com' }),
    googleClient: async (api: string) => makeGcpClient(api),
    guardGcp: (x: any) => x,
  };
});

import { collectAwsReferenceArch } from '../../providers/aws/reference-arch.ts';
import { collectGcpReferenceArch } from '../../providers/gcp/reference-arch.ts';

const CTX = { runId: '00000000-0000-0000-0000-000000000000', frmrVersion: 'test' };

function assertSchemaValid(ev: EvidenceFile): void {
  const r = validateEvidenceFile(JSON.parse(JSON.stringify(ev)));
  if (!r.valid) {
    const first = r.errors[0];
    throw new Error(`schema invalid: ${first?.instancePath} ${first?.message}`);
  }
}

// A fixture that makes all ten AWS checks pass.
const awsHardened = {
  ListKeys: { Keys: [{ KeyId: 'k1' }, { KeyId: 'k2' }] },
  DescribeKey: () => ({ KeyMetadata: { KeyManager: 'CUSTOMER' } }),
  GetEnabledStandards: {
    StandardsSubscriptions: [
      { StandardsArn: 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0' },
      { StandardsArn: 'arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0' },
    ],
  },
  ListFirewalls: { Firewalls: [{ FirewallName: 'fw-egress' }] },
  DescribeFlowLogs: { FlowLogs: [{ FlowLogStatus: 'ACTIVE' }] },
  ListPolicies: { Policies: [{ Name: 'deny-root' }, { Name: 'FullAWSAccess' }] },
  ListDelegatedAdministrators: { DelegatedAdministrators: [{ Id: '1' }] },
  ListAWSServiceAccessForOrganization: {
    EnabledServicePrincipals: [
      { ServicePrincipal: 'guardduty.amazonaws.com' },
      { ServicePrincipal: 'securityhub.amazonaws.com' },
      { ServicePrincipal: 'config.amazonaws.com' },
      { ServicePrincipal: 'cloudtrail.amazonaws.com' },
      { ServicePrincipal: 'access-analyzer.amazonaws.com' },
    ],
  },
  DescribeTrails: { trailList: [{ Name: 'org-trail', CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:111122223333:log-group:ct' }] },
  ListBackupPlans: { BackupPlansList: [{ BackupPlanId: 'p1' }] },
  ListBackupSelections: { BackupSelectionsList: [{ SelectionId: 's1', IamRoleArn: 'arn:aws:iam::111122223333:role/backup' }] },
  ListBuckets: { Buckets: [{ Name: 'app-data' }] },   // no tf-state bucket → state-integrity passes
  ListTables: { TableNames: [] },
  DescribeInstances: { Reservations: [] },             // no AMI pattern set → passes
};

describe('AWS reference-architecture audit (AUDIT-REFARCH-AWS)', () => {
  beforeEach(() => setFakeResponses({}));

  it('passes every check in a fully-hardened environment', async () => {
    setFakeResponses(awsHardened);
    const ev = await collectAwsReferenceArch(makeAwsAuth('us-east-1'), '111122223333', CTX);

    expect(ev.ksi_id).toBe('AUDIT-REFARCH-AWS');
    expect(ev.scope).toBe('CLOUD');
    expect(ev.providers[0]?.provider).toBe('aws');
    expect(ev.providers[0]?.account_id).toBe('111122223333');

    const byRule = Object.fromEntries(ev.providers[0]!.findings.map((f) => [f.rule, f.passed]));
    expect(byRule['aws.kms.customer_managed_keys_in_use']).toBe(true);
    expect(byRule['aws.securityhub.standards_enrolled']).toBe(true);
    expect(byRule['aws.networkfirewall.present']).toBe(true);
    expect(byRule['aws.vpc.flow_logs_active']).toBe(true);
    expect(byRule['aws.organizations.scps_and_delegated_admin']).toBe(true);
    expect(byRule['aws.organizations.security_services_trusted']).toBe(true);
    expect(byRule['aws.cloudtrail.delivers_to_cloudwatch']).toBe(true);
    expect(byRule['aws.backup.selection_coverage']).toBe(true);
    expect(ev.rollup.failing_findings).toBe(0);
    assertSchemaValid(ev);
  });

  it('fails-open (no throw, schema valid) on an empty/degraded environment', async () => {
    setFakeResponses({});   // every call returns {}
    const ev = await collectAwsReferenceArch(makeAwsAuth('us-east-1'), '111122223333', CTX);

    expect(ev.ksi_id).toBe('AUDIT-REFARCH-AWS');
    expect(ev.providers[0]!.findings.length).toBe(10);
    // Customer-managed-key / Security Hub / firewall / flow-log / SCP checks fail
    // when nothing is configured.
    const kms = ev.providers[0]!.findings.find((f) => f.rule === 'aws.kms.customer_managed_keys_in_use');
    expect(kms?.passed).toBe(false);
    expect(kms?.gap?.affected_resources.length ?? 0).toBeGreaterThanOrEqual(1);
    assertSchemaValid(ev);
  });

  it('flags off-pattern AMIs when CLOUD_EVIDENCE_APPROVED_AMI_PATTERN is set', async () => {
    const prev = process.env.CLOUD_EVIDENCE_APPROVED_AMI_PATTERN;
    process.env.CLOUD_EVIDENCE_APPROVED_AMI_PATTERN = '^ami-approved';
    try {
      setFakeResponses({
        ...awsHardened,
        DescribeInstances: { Reservations: [{ Instances: [{ InstanceId: 'i-bad', ImageId: 'ami-rogue123' }] }] },
      });
      const ev = await collectAwsReferenceArch(makeAwsAuth('us-east-1'), '111122223333', CTX);
      const ami = ev.providers[0]!.findings.find((f) => f.rule === 'aws.ec2.approved_ami_provenance');
      expect(ami?.passed).toBe(false);
      expect(ami?.gap?.affected_resources.some((r) => r.identifier === 'i-bad')).toBe(true);
      assertSchemaValid(ev);
    } finally {
      if (prev === undefined) delete process.env.CLOUD_EVIDENCE_APPROVED_AMI_PATTERN;
      else process.env.CLOUD_EVIDENCE_APPROVED_AMI_PATTERN = prev;
    }
  });
});

describe('GCP reference-architecture audit (AUDIT-REFARCH-GCP)', () => {
  beforeEach(() => { gcpState.routes = {}; });

  it('skips org-scoped checks with warnings when no organization is configured', async () => {
    const ev = await collectGcpReferenceArch('proj-1', { ...CTX, organizationId: null });

    expect(ev.ksi_id).toBe('AUDIT-REFARCH-GCP');
    expect(ev.scope).toBe('CLOUD');
    expect(ev.providers[0]?.provider).toBe('gcp');
    expect(ev.providers[0]?.project_id).toBe('proj-1');

    const skips = ev.rollup.warnings.filter((w) => /skipped: no organization_id/i.test(w));
    expect(skips.length).toBe(4);   // Assured Workloads, VPC-SC, SCC, group-admin
    // Org-scoped findings must NOT be present (they were skipped, not failed).
    const rules = ev.providers[0]!.findings.map((f) => f.rule);
    expect(rules).not.toContain('gcp.assured_workloads.fedramp');
    expect(rules).not.toContain('gcp.vpc_service_controls.perimeter');
    assertSchemaValid(ev);
  });

  it('evaluates the Assured Workloads check when an org + FedRAMP workload exist', async () => {
    gcpState.routes = {
      'assuredworkloads:organizations.locations.workloads.list': {
        data: { workloads: [{ complianceRegime: 'FEDRAMP_MODERATE', name: 'aw-1' }] },
      },
    };
    const ev = await collectGcpReferenceArch('proj-1', { ...CTX, organizationId: '123456789' });
    const aw = ev.providers[0]!.findings.find((f) => f.rule === 'gcp.assured_workloads.fedramp');
    expect(aw?.passed).toBe(true);
    assertSchemaValid(ev);
  });
});
