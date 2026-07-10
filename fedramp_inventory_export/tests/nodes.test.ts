import { describe, it, expect } from 'vitest';
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import { nodeAnalysisTable, clusterNodeSummaryTable, buildNodeTables } from '../src/nodes.ts';

function node(p: Partial<CloudAsset>): CloudAsset {
  return { provider: 'aws', uniqueId: p.uniqueId ?? 'arn:x', resourceType: 'AWS::EC2::Instance', ...p } as CloudAsset;
}

const ASSETS: CloudAsset[] = [
  { provider: 'aws', uniqueId: 'arn:eks', resourceType: 'AWS::EKS::Cluster', function: 'prod-k8s-eks-pri', softwareDatabaseNameVersion: 'Amazon EKS 1.33', publicFacing: false } as CloudAsset,
  node({ uniqueId: 'arn:i/i-1', k8sCluster: 'prod-k8s-eks-pri', karpenterNodePool: 'default', nodeGroup: 'default', hardwareMakeModel: 'AWS EC2 m8a.2xlarge', nodeOsFamily: 'Bottlerocket', osNameVersion: 'Bottlerocket 1.62.1', architecture: 'x86_64', fipsTagged: true, location: 'us-gov-west-1a', state: 'running' }),
  node({ uniqueId: 'arn:i/i-2', k8sCluster: 'prod-k8s-eks-pri', karpenterNodePool: 'gpu', nodeGroup: 'gpu', hardwareMakeModel: 'AWS EC2 g5g.xlarge', nodeOsFamily: 'Bottlerocket', architecture: 'arm64', fipsTagged: true, location: 'us-gov-west-1b', state: 'running' }),
  node({ uniqueId: 'arn:i/i-bastion', hardwareMakeModel: 'AWS EC2 t3.micro' }), // not a node (no cluster)
];

describe('node analysis (Prisma Defender)', () => {
  it('lists only worker nodes with a Defender mode + Bottlerocket note', () => {
    const t = nodeAnalysisTable(ASSETS);
    expect(t.rows).toHaveLength(2);           // bastion excluded
    const n1 = t.rows.find((r) => r['Node (Instance)'] === 'i-1')!;
    expect(n1['Defender Mode']).toContain('Bottlerocket');
    expect(n1['Defender Notes']).toMatch(/DaemonSet|host mounts/i);
    const gpu = t.rows.find((r) => r['Node (Instance)'] === 'i-2')!;
    expect(gpu['Defender Notes']).toMatch(/arm64/i);  // Graviton image note
  });

  it('rolls up per cluster with node count + OS mix + Defender approach', () => {
    const t = clusterNodeSummaryTable(ASSETS);
    expect(t.rows).toHaveLength(1);
    const r = t.rows[0]!;
    expect(r['Cluster']).toBe('prod-k8s-eks-pri');
    expect(r['Worker Nodes']).toBe('2');
    expect(r['EKS Version']).toBe('1.33');
    expect(r['Endpoint']).toBe('private');
    expect(r['Defender Approach']).toMatch(/Bottlerocket/);
    expect(r['Defenders Needed (≈)']).toBe('2');   // one DaemonSet pod per node
    expect(r['FIPS-Tagged Nodes']).toBe('2/2');
  });

  it('emits no node sheets when there are no worker nodes', () => {
    expect(buildNodeTables([node({ uniqueId: 'arn:x' })])).toHaveLength(0);
  });
});
