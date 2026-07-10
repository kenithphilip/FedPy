/**
 * Cluster / network attribution — "where does this asset live or flow from?"
 *
 * Mirrors a per-resource cluster/network attribution model so a reader can trace
 * each resource to its owning grouping top-to-bottom:
 *   1. EKS/Kubernetes cluster  — from cluster tags (kubernetes.io/cluster/<name>,
 *      eks:cluster-name, ClusterName) or the cluster's own name.
 *   2. VPC / network           — from vlanNetworkId (vpc-.../subnet-...) or a
 *      Name/vpc tag, for VPC-attached resources with no cluster tag.
 *   3. Account-wide            — global/account-scoped resources (IAM, S3, KMS,
 *      Config, org) that don't belong to a single cluster or VPC.
 *
 * Pure + deterministic. Attribution is best-effort and never fabricated: an asset
 * with no cluster/VPC signal is honestly "account-wide".
 */
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';

export const ACCOUNT_WIDE = 'account-wide';

/** Tag keys (lowercased) that name an owning EKS/K8s cluster. */
const CLUSTER_TAG_KEYS = ['eks:cluster-name', 'clustername', 'cluster', 'kubernetes.io/cluster'];

/** Extract the cluster name from an asset's tags, if any. */
function clusterFromTags(tags: Record<string, string> | undefined): string | null {
  if (!tags) return null;
  const lower = new Map(Object.entries(tags).map(([k, v]) => [k.toLowerCase(), v]));
  // Direct value tags.
  for (const k of ['eks:cluster-name', 'clustername', 'cluster']) {
    const v = lower.get(k);
    if (v && v.trim()) return v.trim();
  }
  // kubernetes.io/cluster/<name>=owned|shared — the name is in the KEY.
  for (const [k] of lower) {
    const m = /^kubernetes\.io\/cluster\/(.+)$/.exec(k);
    if (m && m[1]) return m[1];
    const m2 = /^k8s\.io\/cluster-autoscaler\/(.+)$/.exec(k);
    if (m2 && m2[1] && m2[1] !== 'enabled') return m2[1];
  }
  return null;
}

/** The VPC id from vlanNetworkId ("vpc-x" or "vpc-x/subnet-y") or a tag. */
function vpcOf(a: CloudAsset): string | null {
  const vlan = a.vlanNetworkId ?? '';
  const m = /(vpc-[0-9a-f]+)/i.exec(vlan);
  if (m) return m[1]!;
  // EKS cluster resources: the cluster IS its own grouping (handled by caller).
  return null;
}

export interface Attribution {
  /** The grouping this asset is attributed to (cluster name, vpc id, or account-wide). */
  group: string;
  /** How the attribution was derived — shown so a reviewer can trust/trace it. */
  basis: 'eks-cluster-tag' | 'eks-cluster-name' | 'vpc' | 'account-wide';
}

/**
 * Attribute a single asset to its owning cluster / VPC / account-wide grouping.
 * EKS clusters are their own group; cluster-tagged resources roll up to the
 * cluster; other VPC-attached resources roll up to the VPC; everything else is
 * account-wide.
 */
export function attributeAsset(a: CloudAsset): Attribution {
  const rt = a.resourceType ?? '';
  // An EKS cluster itself is the grouping.
  if (/^AWS::EKS::Cluster$/.test(rt) && a.function) {
    return { group: a.function, basis: 'eks-cluster-name' };
  }
  const clusterTag = clusterFromTags(a.tags);
  if (clusterTag) return { group: clusterTag, basis: 'eks-cluster-tag' };
  const vpc = vpcOf(a);
  if (vpc) return { group: vpc, basis: 'vpc' };
  return { group: ACCOUNT_WIDE, basis: 'account-wide' };
}

/** Rank so account-wide sorts last; named groups alphabetical. */
export function groupRank(group: string): [number, string] {
  return [group === ACCOUNT_WIDE ? 1 : 0, group];
}
