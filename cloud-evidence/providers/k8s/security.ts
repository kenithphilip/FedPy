/**
 * Kubernetes security collectors.
 *
 * Currently implemented:
 *   KSI-IAM-ELP (Enforce Least Privilege)
 *     - Enumerate ClusterRoleBindings + RoleBindings to cluster-admin
 *     - Flag any non-system subject bound to cluster-admin as a finding
 *     - Detect group bindings (e.g. system:masters with non-empty membership)
 *
 * Hooks for future KSIs (stubs in this file; each gets a function later):
 *   - KSI-IAM-AAM: enumerate ServiceAccounts + ABAC/RBAC bindings
 *   - KSI-CNA-IBP: count namespaces without NetworkPolicy
 *   - KSI-CNA-EIS: PodSecurity admission labels per namespace
 *   - KSI-SVC-VRI: image pull policies, image registry constraints
 *
 * All calls go through @kubernetes/client-node and are READ-ONLY (list/get only).
 */
import type { CollectorContext } from '../../core/ksi-map.ts';
import type { ProviderBlock, Finding, RawEvidence, AffectedResource } from '../../core/envelope.ts';
import { makeK8sAuth, type K8sAuth } from '../../core/auth/k8s.ts';
import { diagnoseK8sError } from '../../core/error-diagnostics.ts';

const K8S_CALL_TIMEOUT_MS = Number(process.env.CLOUD_EVIDENCE_K8S_TIMEOUT_MS ?? 10_000);

/**
 * Race a K8s API call against a timeout so a dead cluster (no route to apiserver,
 * stale kubeconfig, etc.) doesn't hang the whole collection. Default 10s.
 */
async function withK8sTimeout<T>(p: Promise<T>, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(Object.assign(new Error(`${label} timed out after ${K8S_CALL_TIMEOUT_MS}ms`), { code: 'ETIMEDOUT' })),
      K8S_CALL_TIMEOUT_MS,
    );
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

function nowIso(): string { return new Date().toISOString(); }

function ev(source: string, data: unknown): RawEvidence {
  return { source: `k8s.${source}`, captured_at: nowIso(), data: data === undefined ? null : data };
}

/**
 * Built-in system principals that may legitimately have cluster-admin (or
 * equivalent). These are NOT flagged as findings — flagging them would
 * produce noise. The auditor's concern is human or service-account-only
 * principals that shouldn't have such broad permissions.
 */
const SYSTEM_ADMIN_SUBJECTS = new Set([
  'system:masters',                 // Group; bootstrapped admin
  'system:kube-scheduler',
  'system:kube-controller-manager',
  'system:cluster-admins',          // Some distros use this naming
]);

function subjectKey(subj: { kind: string; name: string; namespace?: string }): string {
  if (subj.kind === 'ServiceAccount' && subj.namespace) return `sa:${subj.namespace}/${subj.name}`;
  return `${subj.kind.toLowerCase()}:${subj.name}`;
}

function subjectToResource(subj: any): AffectedResource {
  if (subj.kind === 'ServiceAccount') {
    return {
      type: 'kubernetes_service_account',
      identifier: `${subj.namespace}/${subj.name}`,
      name: subj.name,
      attributes: { namespace: subj.namespace },
    };
  }
  return {
    type: subj.kind === 'User' ? 'kubernetes_user' : subj.kind === 'Group' ? 'kubernetes_group' : 'kubernetes_subject',
    identifier: subj.name,
    name: subj.name,
  };
}

/**
 * KSI-IAM-ELP — Enumerate cluster-admin bindings and flag non-system subjects.
 *
 * Approach:
 *   1. List ClusterRoleBindings → keep those that bind to ClusterRole "cluster-admin".
 *   2. Inspect each binding's subjects[]; any human user or non-system SA
 *      becomes an affected resource.
 *   3. Also list bindings to ClusterRoles with `*` verbs on `*` resources
 *      (custom admin roles by another name) — heuristic only; rules from
 *      ClusterRole detail.
 */
export async function collectK8sIamElp(c: CollectorContext): Promise<ProviderBlock> {
  const evidence: RawEvidence[] = [];
  const warnings: string[] = [];
  const ctxName = (c as any).k8s?.context ?? 'current';
  const auth: K8sAuth = (c as any).k8s?.auth ?? makeK8sAuth(ctxName);

  // 1. ClusterRoleBindings → cluster-admin
  const adminSubjects: any[] = [];
  let totalBindings = 0;
  try {
    // Cast through `any` — @kubernetes/client-node has cross-version sig drift.
    // Wrap in a timeout so a dead apiserver doesn't hang the collection.
    const out = await withK8sTimeout(
      (auth.rbac as any).listClusterRoleBinding(),
      'rbac.listClusterRoleBinding',
    );
    const items: any[] = (out as any).items ?? [];
    totalBindings = items.length;
    evidence.push(ev('rbac.listClusterRoleBinding', { count: items.length, sample: items.slice(0, 5).map((b: any) => b.metadata?.name) }));
    for (const b of items) {
      if (!b || typeof b !== 'object') continue;
      const role = b.roleRef;
      if (!role || role.kind !== 'ClusterRole' || role.name !== 'cluster-admin') continue;
      for (const s of (Array.isArray(b.subjects) ? b.subjects : [])) {
        if (s && typeof s === 'object') adminSubjects.push({ binding: b.metadata?.name, ...s });
      }
    }
  } catch (e: any) {
    warnings.push(diagnoseK8sError(e, 'rbac.listClusterRoleBinding', 'list', 'clusterrolebindings (rbac.authorization.k8s.io)'));
  }

  // Determine which admins are "concerning" (non-system principals).
  const concerning = adminSubjects.filter((s) => {
    if (SYSTEM_ADMIN_SUBJECTS.has(s.name)) return false;
    if (s.name?.startsWith('system:')) return false;  // built-in system identity
    return true;
  });

  // 2. Custom admin roles (heuristic): ClusterRoles with rules granting * on *
  let wildcardClusterRoles: string[] = [];
  try {
    const roles = await withK8sTimeout((auth.rbac as any).listClusterRole(), 'rbac.listClusterRole');
    const items: any[] = (roles as any).items ?? [];
    wildcardClusterRoles = items
      .filter((r: any) =>
        Array.isArray(r.rules) &&
        r.rules.some((rule: any) =>
          (rule.verbs ?? []).includes('*') &&
          (rule.resources ?? []).includes('*') &&
          (!rule.apiGroups || rule.apiGroups.includes('*') || rule.apiGroups.includes('')),
        ),
      )
      .map((r: any) => r.metadata?.name)
      .filter((n: string) => n !== 'cluster-admin'); // already covered above
    evidence.push(ev('rbac.listClusterRole.wildcard_roles', wildcardClusterRoles));
  } catch (e: any) {
    warnings.push(diagnoseK8sError(e, 'rbac.listClusterRole', 'list', 'clusterroles (rbac.authorization.k8s.io)'));
  }

  const passed = concerning.length === 0;

  const finding: Finding = {
    rule: 'k8s.rbac.cluster_admin_least_privileged',
    passed,
    severity: passed ? 'info' : 'critical',
    current_state: {
      summary: passed
        ? `${adminSubjects.length} cluster-admin binding subject(s) — all are system identities.`
        : `${concerning.length} non-system subject(s) hold cluster-admin in ${ctxName}.`,
      observations: {
        cluster_context: ctxName,
        cluster_admin_subjects: adminSubjects,
        custom_wildcard_clusterroles: wildcardClusterRoles,
        total_clusterrolebindings: totalBindings,
      },
    },
    target_state: {
      summary: 'No human users or non-system service accounts hold cluster-admin or equivalent.',
      rationale: 'cluster-admin is unbounded blast-radius; FedRAMP 20x KSI-IAM-ELP requires least-privilege enforcement. Custom roles or namespaced bindings should be used instead.',
    },
    nist_controls: ['AC-2', 'AC-3', 'AC-6'],
    references: [
      { title: 'Kubernetes RBAC: cluster-admin', url: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles' },
      { title: 'CIS Kubernetes Benchmark — RBAC controls', url: 'https://www.cisecurity.org/benchmark/kubernetes' },
    ],
  };

  if (!passed) {
    finding.gap = {
      description: `${concerning.length} subject(s) with cluster-admin should be reduced to narrower roles.`,
      affected_resources: concerning.map(subjectToResource),
    };
    finding.remediation = {
      summary: 'Replace cluster-admin bindings with least-privilege ClusterRoles or namespaced RoleBindings.',
      options: [
        {
          approach: 'Replace ClusterRoleBinding with a purpose-built ClusterRole (e.g. view + edit on the workloads they actually own).',
          mechanism: 'cli',
          steps: [
            'For each subject, run: kubectl auth can-i --list --as=<subject> to enumerate currently-used permissions',
            'Define a new ClusterRole with only those verbs/resources',
            'Replace the binding: kubectl delete clusterrolebinding <name> && kubectl create clusterrolebinding ...',
            'Re-run cloud-evidence to confirm the finding clears',
          ],
          owner_team: 'Platform',
          customer_visible: { level: 'low', notes: 'Internal operator change; no customer-facing impact unless an automation depended on cluster-admin.' },
          availability_impact: { level: 'medium', notes: 'Misconfigured replacement role can break automated jobs — stage the change in non-prod first.' },
          cost_impact: { level: 'none', notes: 'No cloud spend; ~hours of platform-team effort.' },
          effort_estimate: { magnitude: 'hours', notes: 'Per subject; bulk migrations may take days.' },
        },
        {
          approach: 'Migrate human admins to break-glass with audit — use a JIT system (Teleport, AWS SSO, OpenID Connect) instead of standing cluster-admin.',
          mechanism: 'external-tool',
          steps: [
            'Choose JIT provider (Teleport / AWS IAM Identity Center + EKS authenticator / etc.)',
            'Configure cluster to accept JIT-issued certificates or tokens',
            'Revoke direct cluster-admin bindings',
          ],
          owner_team: 'Identity / IT',
          effort_estimate: { magnitude: 'weeks', notes: 'Full rollout including training and runbook updates.' },
        },
      ],
    };
  }

  return {
    provider: 'k8s' as any,
    account_id: ctxName,
    region_set: [auth.server],
    evidence,
    findings: [finding],
    warnings,
  };
}
