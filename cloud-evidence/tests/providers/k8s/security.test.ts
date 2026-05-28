/**
 * Tests for providers/k8s/security.ts — cluster-admin enumeration.
 *
 * Mocks core/auth/k8s.ts with a fake that returns canned RBAC API responses.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const fakeRbacResponses: {
  listClusterRoleBinding?: any;
  listClusterRole?: any;
} = {};

vi.mock('../../../core/auth/k8s.ts', () => ({
  makeK8sAuth: (context: string) => ({
    context,
    server: 'https://example.k8s.local',
    core: {},
    rbac: {
      listClusterRoleBinding: vi.fn(async () => fakeRbacResponses.listClusterRoleBinding ?? { items: [] }),
      listClusterRole: vi.fn(async () => fakeRbacResponses.listClusterRole ?? { items: [] }),
    },
    network: {},
    apps: {},
    apiextensions: {},
  }),
  listK8sContexts: () => [],
  whoAmIK8s: async () => ({ context: 'test', server: 'x', version: 'v1' }),
}));

import { collectK8sIamElp } from '../../../providers/k8s/security.ts';

beforeEach(() => {
  fakeRbacResponses.listClusterRoleBinding = undefined;
  fakeRbacResponses.listClusterRole = undefined;
});

describe('collectK8sIamElp', () => {
  it('passes when only system identities hold cluster-admin', async () => {
    fakeRbacResponses.listClusterRoleBinding = {
      items: [
        {
          metadata: { name: 'cluster-admin-binding' },
          roleRef: { kind: 'ClusterRole', name: 'cluster-admin' },
          subjects: [{ kind: 'Group', name: 'system:masters' }],
        },
      ],
    };
    const result = await collectK8sIamElp({ k8s: { context: 'prod-cluster' } });
    const f = result.findings.find((x) => x.rule === 'k8s.rbac.cluster_admin_least_privileged');
    expect(f?.passed).toBe(true);
    expect(f?.severity).toBe('info');
  });

  it('fails when a human user has cluster-admin', async () => {
    fakeRbacResponses.listClusterRoleBinding = {
      items: [
        {
          metadata: { name: 'cluster-admin-binding' },
          roleRef: { kind: 'ClusterRole', name: 'cluster-admin' },
          subjects: [
            { kind: 'Group', name: 'system:masters' },
            { kind: 'User', name: 'alice@example.com' },
          ],
        },
      ],
    };
    const result = await collectK8sIamElp({ k8s: { context: 'prod-cluster' } });
    const f = result.findings.find((x) => x.rule === 'k8s.rbac.cluster_admin_least_privileged');
    expect(f?.passed).toBe(false);
    expect(f?.severity).toBe('critical');
    expect(f?.gap?.affected_resources.length).toBe(1);
    expect(f?.gap?.affected_resources[0].identifier).toBe('alice@example.com');
    expect(f?.remediation?.options.length).toBeGreaterThan(0);
  });

  it('fails when a ServiceAccount has cluster-admin', async () => {
    fakeRbacResponses.listClusterRoleBinding = {
      items: [
        {
          metadata: { name: 'sa-admin' },
          roleRef: { kind: 'ClusterRole', name: 'cluster-admin' },
          subjects: [{ kind: 'ServiceAccount', name: 'super-controller', namespace: 'kube-system' }],
        },
      ],
    };
    const result = await collectK8sIamElp({ k8s: { context: 'prod' } });
    const f = result.findings.find((x) => x.rule === 'k8s.rbac.cluster_admin_least_privileged');
    expect(f?.passed).toBe(false);
    expect(f?.gap?.affected_resources[0].type).toBe('kubernetes_service_account');
    expect(f?.gap?.affected_resources[0].identifier).toBe('kube-system/super-controller');
  });

  it('detects custom wildcard ClusterRoles (admin-by-another-name)', async () => {
    fakeRbacResponses.listClusterRoleBinding = { items: [] };
    fakeRbacResponses.listClusterRole = {
      items: [
        {
          metadata: { name: 'super-admin' },
          rules: [{ verbs: ['*'], resources: ['*'], apiGroups: ['*'] }],
        },
        { metadata: { name: 'view' }, rules: [{ verbs: ['get', 'list'], resources: ['pods'] }] },
      ],
    };
    const result = await collectK8sIamElp({ k8s: { context: 'prod' } });
    const wildcards = result.evidence.find((e) => e.source === 'k8s.rbac.listClusterRole.wildcard_roles')?.data as string[];
    expect(wildcards).toContain('super-admin');
    expect(wildcards).not.toContain('view');
  });

  it('produces v3-schema-shaped evidence', async () => {
    fakeRbacResponses.listClusterRoleBinding = { items: [] };
    const result = await collectK8sIamElp({ k8s: { context: 'prod' } });
    expect(result.provider).toBe('k8s');
    expect(result.account_id).toBe('prod');
    for (const f of result.findings) {
      expect(f.current_state?.summary).toBeTruthy();
      expect(f.target_state?.summary).toBeTruthy();
      expect(f.target_state?.rationale).toBeTruthy();
    }
  });
});
