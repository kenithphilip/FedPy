/**
 * Tests for core/inventory-emit.ts — diff + OSCAL + CMDB projections (INV-18/19/21).
 */
import { describe, it, expect } from 'vitest';
import { diffInventory, assetsToOscalInventory, assetsToCmdbRecords } from '../../core/inventory-emit.ts';
import type { CloudAsset } from '../../core/inventory-workbook.ts';

describe('diffInventory', () => {
  it('detects added, removed, and changed assets', () => {
    const prev: CloudAsset[] = [
      { provider: 'aws', uniqueId: 'keep', state: 'running' },
      { provider: 'aws', uniqueId: 'gone' },
    ];
    const curr: CloudAsset[] = [
      { provider: 'aws', uniqueId: 'keep', state: 'stopped' },  // changed: state
      { provider: 'aws', uniqueId: 'new' },
    ];
    const d = diffInventory(prev, curr);
    expect(d.added).toEqual(['new']);
    expect(d.removed).toEqual(['gone']);
    expect(d.changed).toEqual([{ id: 'keep', fields: ['state'] }]);
    expect(d.previous_count).toBe(2);
    expect(d.current_count).toBe(2);
  });
  it('reports no changes for identical inventories', () => {
    const a: CloudAsset[] = [{ provider: 'gcp', uniqueId: 'x', state: 'RUNNING' }];
    const d = diffInventory(a, a);
    expect(d.added).toEqual([]); expect(d.removed).toEqual([]); expect(d.changed).toEqual([]);
  });
});

describe('assetsToOscalInventory', () => {
  it('emits one inventory-item per asset with stable uuid + props', () => {
    const items = assetsToOscalInventory([
      { provider: 'aws', uniqueId: 'arn:x', assetType: 'Compute Instance', resourceType: 'AWS::EC2::Instance', accountId: '111', location: 'us-east-1a', ips: ['10.0.0.1'], publicFacing: false, environment: 'prod', systemOwner: 'alice' },
    ]);
    expect(items).toHaveLength(1);
    const it = items[0]!;
    expect(it.uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
    const props = Object.fromEntries(it.props.map((p) => [p.name, p.value]));
    expect(props['asset-id']).toBe('arn:x');
    expect(props['cloud-provider']).toBe('aws');
    expect(props['public']).toBe('no');
    expect(props['environment']).toBe('prod');
    expect(it['responsible-parties']?.[0]?.remarks).toBe('alice');
  });
  it('produces a deterministic uuid for the same asset id', () => {
    const a: CloudAsset = { provider: 'aws', uniqueId: 'arn:same' };
    expect(assetsToOscalInventory([a])[0]!.uuid).toBe(assetsToOscalInventory([a])[0]!.uuid);
  });
});

describe('assetsToCmdbRecords', () => {
  it('maps asset types to ServiceNow CI classes and carries key attrs', () => {
    const recs = assetsToCmdbRecords([
      { provider: 'aws', uniqueId: 'arn:i', assetType: 'Compute Instance', ips: ['10.0.0.1'], dns: 'h.local', state: 'running', systemOwner: 'alice', environment: 'prod' },
      { provider: 'gcp', uniqueId: '//x/bucket', assetType: 'Object Storage Bucket' },
      { provider: 'aws', uniqueId: 'arn:db', assetType: 'Database' },
    ]);
    expect(recs[0]!.sys_class_name).toBe('cmdb_ci_vm_instance');
    expect(recs[0]!.ip_address).toBe('10.0.0.1');
    expect(recs[0]!.fqdn).toBe('h.local');
    expect(recs[0]!.install_status).toBe('running');
    expect(recs[1]!.sys_class_name).toBe('cmdb_ci_storage_volume');
    expect(recs[2]!.sys_class_name).toBe('cmdb_ci_database');
    expect(recs[0]!.discovery_source).toBe('FedPy cloud-evidence');
  });
});
