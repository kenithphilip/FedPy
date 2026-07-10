/**
 * Node analysis + Prisma Cloud Defender deployment planning.
 *
 * Answers "where do Defenders go and what's needed?" for the FedRAMP EKS estate,
 * mirroring a per-cluster node-analysis model but oriented to Defender
 * deployment. Two tables:
 *   1. Per-node — instance, type, OS family, arch, cluster, nodepool/nodegroup,
 *      FIPS tag, and a Defender deployment mode + notes.
 *   2. Per-cluster rollup — node count, versions, OS mix, Defender approach.
 *
 * Prisma Defender facts encoded:
 *   - EKS worker nodes → Defender runs as a DaemonSet (one per node), not a host
 *     install. Bottlerocket (container-optimized, immutable) requires the
 *     DaemonSet + a privileged/host-mount config and a Bottlerocket-compatible
 *     Defender; you cannot install a host package.
 *   - arm64 (Graviton) nodes need an arm64 Defender image.
 *   - FIPS estate → use the Defender image/console configured for FIPS.
 *
 * Pure + deterministic.
 */
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { ReportTable } from './tables.ts';

/** Is this asset an EKS/K8s worker node (has a cluster attribution)? */
function isWorkerNode(a: CloudAsset): boolean {
  return (a.resourceType ?? '') === 'AWS::EC2::Instance' && !!a.k8sCluster;
}

/** Defender deployment mode + note for a node, from its OS family + arch. */
function defenderPlan(os: string | null | undefined, arch: string | null | undefined): { mode: string; note: string } {
  const o = (os ?? '').toLowerCase();
  const a = (arch ?? '').toLowerCase();
  const archNote = a.includes('arm') ? ' arm64 Defender image required (Graviton).' : '';
  if (o.includes('bottlerocket')) {
    return { mode: 'DaemonSet (Bottlerocket)', note: `Container-optimized/immutable OS — deploy the Defender DaemonSet with the Bottlerocket-compatible image + host mounts; no host-package install.${archNote}` };
  }
  if (o.includes('amazon linux') || o.includes('ubuntu') || o.includes('rhel')) {
    return { mode: 'DaemonSet (Linux)', note: `Standard EKS Linux node — Defender DaemonSet (or host Defender if run outside K8s).${archNote}` };
  }
  if (o.includes('windows')) {
    return { mode: 'DaemonSet (Windows)', note: `Windows node — use the Windows Defender container image.${archNote}` };
  }
  return { mode: 'DaemonSet', note: `OS not identified from cloud metadata — confirm node OS before selecting the Defender image.${archNote}` };
}

const NODE_COLUMNS = [
  'Cluster', 'Node (Instance)', 'Instance Type', 'OS Family', 'OS Version', 'Arch',
  'Node Pool / Group', 'Region / AZ', 'FIPS Tagged', 'State', 'Private IPs',
  'Defender Mode', 'Defender Notes',
] as const;

export function nodeAnalysisTable(assets: CloudAsset[]): ReportTable {
  const rows = assets.filter(isWorkerNode)
    .map((a) => {
      const plan = defenderPlan(a.nodeOsFamily, a.architecture);
      return {
        'Cluster': a.k8sCluster ?? '',
        'Node (Instance)': a.uniqueId.split('/').pop() ?? a.uniqueId,
        'Instance Type': (a.hardwareMakeModel ?? '').replace(/^AWS EC2 /, ''),
        'OS Family': a.nodeOsFamily ?? '',
        'OS Version': a.osNameVersion ?? '',
        'Arch': a.architecture ?? '',
        'Node Pool / Group': a.nodeGroup ?? a.karpenterNodePool ?? '',
        'Region / AZ': a.location ?? '',
        'FIPS Tagged': a.fipsTagged === true ? 'Yes' : a.fipsTagged === false ? 'No' : '',
        'State': a.state ?? '',
        'Private IPs': (a.ips ?? []).join('; '),
        'Defender Mode': plan.mode,
        'Defender Notes': plan.note,
      };
    })
    .sort((x, y) => x['Cluster'].localeCompare(y['Cluster']) || x['Node Pool / Group'].localeCompare(y['Node Pool / Group']) || x['Node (Instance)'].localeCompare(y['Node (Instance)']));
  return { name: 'node_analysis', title: 'Node Analysis (Defender)', columns: [...NODE_COLUMNS], rows };
}

const CLUSTER_COLUMNS = [
  'Cluster', 'EKS Version', 'Endpoint', 'Worker Nodes', 'Node Pools / Groups',
  'OS Families', 'Architectures', 'Instance Types', 'FIPS-Tagged Nodes',
  'Defender Approach', 'Defenders Needed (≈)',
] as const;

/** Per-cluster rollup: the EKS cluster asset + its worker nodes. */
export function clusterNodeSummaryTable(assets: CloudAsset[]): ReportTable {
  const clusters = new Map<string, CloudAsset>();      // cluster name → EKS cluster asset
  for (const a of assets) if ((a.resourceType ?? '') === 'AWS::EKS::Cluster' && a.function) clusters.set(a.function, a);

  const nodesByCluster = new Map<string, CloudAsset[]>();
  for (const a of assets) if (isWorkerNode(a)) {
    const c = a.k8sCluster!;
    (nodesByCluster.get(c) ?? nodesByCluster.set(c, []).get(c)!).push(a);
  }

  const names = new Set<string>([...clusters.keys(), ...nodesByCluster.keys()]);
  const rows = [...names].sort().map((name) => {
    const cl = clusters.get(name);
    const nodes = nodesByCluster.get(name) ?? [];
    const pools = new Set(nodes.map((n) => n.nodeGroup ?? n.karpenterNodePool ?? '(unknown)').filter(Boolean));
    const osFams = new Set(nodes.map((n) => n.nodeOsFamily ?? '(unknown)'));
    const arches = new Set(nodes.map((n) => n.architecture ?? '(unknown)'));
    const types = new Set(nodes.map((n) => (n.hardwareMakeModel ?? '').replace(/^AWS EC2 /, '')).filter(Boolean));
    const fipsNodes = nodes.filter((n) => n.fipsTagged === true).length;
    const bottlerocket = [...osFams].some((o) => o.toLowerCase().includes('bottlerocket'));
    const approach = bottlerocket
      ? 'Defender DaemonSet — Bottlerocket image + host mounts (per node pool)'
      : nodes.length ? 'Defender DaemonSet across all node pools' : 'No worker nodes discovered';
    return {
      'Cluster': name,
      'EKS Version': cl?.softwareDatabaseNameVersion?.replace(/^Amazon EKS /, '') ?? '',
      'Endpoint': cl?.publicFacing === true ? 'public' : cl?.publicFacing === false ? 'private' : '',
      'Worker Nodes': String(nodes.length),
      'Node Pools / Groups': [...pools].sort().join('; '),
      'OS Families': [...osFams].sort().join('; '),
      'Architectures': [...arches].sort().join('; '),
      'Instance Types': [...types].sort().join('; '),
      'FIPS-Tagged Nodes': `${fipsNodes}/${nodes.length}`,
      'Defender Approach': approach,
      'Defenders Needed (≈)': String(nodes.length), // one DaemonSet pod per node
    };
  });
  return { name: 'cluster_node_summary', title: 'Cluster Node Summary', columns: [...CLUSTER_COLUMNS], rows };
}

export function buildNodeTables(assets: CloudAsset[]): ReportTable[] {
  const clusterSummary = clusterNodeSummaryTable(assets);
  const nodeAnalysis = nodeAnalysisTable(assets);
  // Only include if there are worker nodes to analyze.
  return nodeAnalysis.rows.length ? [clusterSummary, nodeAnalysis] : [];
}
