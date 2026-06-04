/**
 * Tests for providers/azure/vdr-scan.ts → collectVdrScan (KSI-AFR-VDR).
 *
 * Exercises both the Resource-Graph-routed Defender assessment query AND the
 * KEV-catalog join. We set CLOUD_EVIDENCE_KEV_PATH to a temp file per test so
 * the KEV membership lookup is deterministic.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateEvidenceFile } from '../../../core/schema.ts';

const _state = vi.hoisted(() => ({
  routes: [] as Array<{ match: string; rows: any[] }>,
  queries: [] as string[],
}));

vi.mock('../../../core/auth/azure.ts', () => ({
  whoAmIAzure: async () => ({ principal: 'test', tenantId: null, appId: null }),
  guardAzure: <T extends object>(c: T) => c,
  resourceGraph: () => ({
    async resources(req: any) {
      _state.queries.push(req.query);
      const route = _state.routes.find((r) => req.query.includes(r.match));
      return { data: route?.rows ?? [] };
    },
  }),
  resources: (_id: string) => ({}),
}));

import { collectVdrScan, assessedResourceId } from '../../../providers/azure/vdr-scan.ts';

function assertSchemaValid(block: any, ksiId: string): void {
  const envelope: any = {
    ksi_id: ksiId, ksi_name: ksiId, ksi_statement: 'smoke', scope: 'HYBRID',
    frmr_version: 'test', run_id: '00000000-0000-0000-0000-000000000000',
    collected_at: '2026-06-01T00:00:00.000Z',
    providers: [block],
    rollup: {
      pass: block.findings.every((f: any) => f.passed),
      passing_findings: block.findings.filter((f: any) => f.passed).length,
      failing_findings: block.findings.filter((f: any) => !f.passed).length,
      warnings: block.warnings ?? [],
      missing_evidence: [], alternatives_in_play: 0,
    },
  };
  const r = validateEvidenceFile(JSON.parse(JSON.stringify(envelope)));
  if (!r.valid) throw new Error(`schema invalid: ${(r.errors[0] as any)?.instancePath} ${(r.errors[0] as any)?.message}`);
}

const ctx = (subs: string[] = ['sub-1']) => ({ azure: { tenant_id: 't', subscription_id: subs[0] ?? null, subscription_ids: subs } });

let tmpDir: string;
let prevKevEnv: string | undefined;
function writeKev(items: Array<{ cveID: string }>): string {
  const path = join(tmpDir, 'kev.json');
  writeFileSync(path, JSON.stringify({ vulnerabilities: items }));
  return path;
}

describe('collectVdrScan (KSI-AFR-VDR Azure)', () => {
  beforeEach(() => {
    _state.routes = []; _state.queries = [];
    tmpDir = mkdtempSync(join(tmpdir(), 'az-vdr-'));
    prevKevEnv = process.env.CLOUD_EVIDENCE_KEV_PATH;
  });

  afterEach(() => {
    if (prevKevEnv === undefined) delete process.env.CLOUD_EVIDENCE_KEV_PATH;
    else process.env.CLOUD_EVIDENCE_KEV_PATH = prevKevEnv;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('PASSES when Defender assessments exist and zero unhealthy match a KEV CVE', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKev([{ cveID: 'CVE-2024-99999' }]);
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [
      { id: '/a/1', name: 'a', subscriptionId: 'sub-1', displayName: 'CVE-2023-1234 in package X', status: 'Unhealthy', description: 'minor' },
      { id: '/a/2', name: 'b', status: 'Healthy', displayName: 'docker base image up to date', description: '' },
    ] }];
    const block = await collectVdrScan(ctx());
    expect(block.findings[0]!.passed).toBe(true);
    assertSchemaValid(block, 'KSI-AFR-VDR');
  });

  it('FAILS when at least one Unhealthy finding references a CISA KEV CVE', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKev([{ cveID: 'CVE-2024-31497' }]);
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [
      { id: '/a/kev', subscriptionId: 'sub-1', displayName: 'Update putty to remediate CVE-2024-31497', status: 'Unhealthy', description: 'critical' },
    ] }];
    const block = await collectVdrScan(ctx());
    expect(block.findings[0]!.passed).toBe(false);
    expect((block.findings[0]!.current_state.observations as any).kev_affected).toBe(1);
  });

  it('FAILS when Defender returns zero assessments at all (no detection feed)', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKev([{ cveID: 'CVE-2024-31497' }]);
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [] }];
    const block = await collectVdrScan(ctx());
    expect(block.findings[0]!.passed).toBe(false);
  });

  it('handles a missing KEV catalog gracefully (warning only; pass if no Unhealthy)', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = join(tmpDir, 'doesnt-exist.json');
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [
      { id: '/a/1', displayName: 'CVE-2023-1234', status: 'Healthy' },
    ] }];
    const block = await collectVdrScan(ctx());
    // With no KEV catalog, any Unhealthy CVE wouldn't match anyway → pass if total >= 1.
    expect(block.findings[0]!.passed).toBe(true);
    expect((block.warnings ?? []).some((w) => w.includes('KEV catalog'))).toBe(true);
  });

  it('extracts and de-duplicates multiple CVEs in a single assessment row', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKev([{ cveID: 'CVE-2024-1111' }, { cveID: 'CVE-2024-2222' }]);
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [
      { id: '/a/multi', displayName: 'Mixed: CVE-2024-1111 and CVE-2024-2222 and CVE-2024-1111 again', status: 'Unhealthy' },
    ] }];
    const block = await collectVdrScan(ctx());
    expect(block.findings[0]!.passed).toBe(false);
    const obs = block.findings[0]!.current_state.observations as any;
    expect(obs.kev_affected).toBe(1); // one ROW that contains KEV CVEs (regardless of how many)
  });

  // INV-S5
  it('surfaces every assessed resource id (healthy + unhealthy) as evidence.assessed_resource_ids', async () => {
    process.env.CLOUD_EVIDENCE_KEV_PATH = writeKev([{ cveID: 'CVE-2024-1' }]);
    _state.routes = [{ match: 'microsoft.security/assessments', rows: [
      { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1/providers/Microsoft.Security/assessments/a1',
        resId: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1',
        displayName: 'unrelated', status: 'Healthy' },
      { id: '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2/providers/Microsoft.Security/assessments/a2',
        resId: '',  // forces fallback to id-stripping
        displayName: 'unrelated', status: 'Unhealthy' },
    ] }];
    const block = await collectVdrScan(ctx());
    const ev = (block.evidence ?? []).find((e) => e.source === 'resourcegraph.defender_assessments_vdr');
    expect(ev).toBeDefined();
    const ids = (ev!.data as any).assessed_resource_ids as string[];
    // Both VMs surface — vm-1 via resId, vm-2 via id-stripping fallback.
    expect(ids).toContain('/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1');
    expect(ids).toContain('/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-2');
  });
});

describe('assessedResourceId helper', () => {
  it('prefers an explicit resourceDetails.Id when present', () => {
    const r = assessedResourceId('/x/providers/Microsoft.Security/assessments/a', '/explicit');
    expect(r).toBe('/explicit');
  });
  it('strips /providers/Microsoft.Security/... from the assessment id when no explicit id', () => {
    const id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1/providers/Microsoft.Security/assessments/a';
    expect(assessedResourceId(id, null)).toBe('/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1');
  });
  it('returns null for null + empty inputs', () => {
    expect(assessedResourceId(null, null)).toBeNull();
    expect(assessedResourceId('', '')).toBeNull();
  });
});
