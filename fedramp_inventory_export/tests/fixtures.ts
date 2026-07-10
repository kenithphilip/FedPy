/**
 * Synthetic, AWS-free fixtures: a small inventory snapshot + a couple of
 * evidence envelopes shaped exactly like FedPy's real output, so the tests
 * exercise the real join / benchmark / writer code paths without any cloud call.
 */
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InventorySnapshot, CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { EvidenceFile } from '../../cloud-evidence/core/envelope.ts';

export function sampleAssets(): CloudAsset[] {
  return [
    {
      provider: 'aws',
      uniqueId: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
      accountId: '111122223333',
      resourceType: 'AWS::EC2::Instance',
      assetType: 'Compute Instance',
      function: 'web-1',
      location: 'us-east-1',
      state: 'running',
      publicFacing: true,
      ips: ['10.0.0.5'],
      osNameVersion: 'Amazon Linux 2',
      encryptionAtRest: true,
      environment: 'prod',
    },
    {
      provider: 'aws',
      uniqueId: 'arn:aws:s3:::my-sensitive-bucket',
      accountId: '111122223333',
      resourceType: 'AWS::S3::Bucket',
      assetType: 'Object Storage',
      function: 'my-sensitive-bucket',
      location: 'global',
      publicFacing: false,
      encryptionAtRest: false,
      dataClassification: 'Sensitive (Macie)',
    },
    {
      provider: 'gcp',
      uniqueId: '//compute.googleapis.com/projects/p/zones/us-central1-a/instances/db-1',
      accountId: 'my-gcp-project',
      resourceType: 'compute.googleapis.com/Instance',
      assetType: 'Compute Instance',
      function: 'db-1',
      location: 'us-central1',
      state: 'running',
      publicFacing: false,
      encryptionAtRest: true,
    },
  ];
}

export function sampleSnapshot(): InventorySnapshot {
  const assets = sampleAssets();
  return {
    generated_at: '2026-07-07T00:00:00.000Z',
    asset_count: assets.length,
    edge_count: 0,
    by_provider: { aws: 2, gcp: 1 },
    by_type: {},
    assets,
    edges: [],
  };
}

/** A KSI-style envelope with one failing finding on the S3 bucket + one pass. */
export function sampleKsiEncryption(): EvidenceFile {
  return {
    ksi_id: 'KSI-CNA-ENC',
    ksi_name: 'Encryption at rest',
    ksi_statement: 'Encrypt data at rest.',
    scope: 'CLOUD',
    frmr_version: 'test',
    run_id: 'run-1',
    collected_at: '2026-07-07T00:00:00.000Z',
    category: 'ksi-indicator',
    family: 'CNA',
    impact_level: 'moderate',
    nist_controls: ['sc-28'],
    providers: [
      {
        provider: 'aws',
        findings: [
          {
            rule: 'aws.s3.encryption_enabled',
            passed: false,
            severity: 'high',
            current_state: { summary: 'Bucket has no default encryption', observations: {} },
            target_state: { summary: 'SSE enabled', rationale: 'SC-28' },
            nist_controls: ['sc-28'],
            gap: {
              description: 'S3 bucket is unencrypted at rest',
              affected_resources: [
                { type: 'aws_s3_bucket', identifier: 'arn:aws:s3:::my-sensitive-bucket', name: 'my-sensitive-bucket' },
              ],
            },
          },
          {
            rule: 'aws.ebs.encryption_enabled',
            passed: true,
            severity: 'info',
            current_state: { summary: 'EC2 volume encrypted', observations: {} },
            target_state: { summary: 'encrypted', rationale: 'SC-28' },
            nist_controls: ['sc-28'],
          },
        ],
        evidence: [],
      },
    ],
    rollup: { pass: false, passing_findings: 1, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

/** An awareness-only FRR (obligates FedRAMP, not the provider). */
export function sampleAwarenessFrr(): EvidenceFile {
  return {
    ksi_id: 'VDR-FRP-CAP',
    ksi_name: 'FedRAMP vuln capability',
    ksi_statement: 'FedRAMP will…',
    scope: 'PROCESS',
    frmr_version: 'test',
    run_id: 'run-1',
    collected_at: '2026-07-07T00:00:00.000Z',
    category: 'frr-requirement',
    family: 'VDR',
    impact_level: 'moderate',
    awareness_only: true,
    actor_scope: 'fedramp',
    nist_controls: ['ra-5'],
    providers: [{ provider: 'aws', findings: [], evidence: [] }],
    rollup: { pass: true, passing_findings: 0, failing_findings: 0, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

/** A KSI with an account-level failing finding (identifier = bare account id). */
export function sampleKsiRootMfa(): EvidenceFile {
  return {
    ksi_id: 'KSI-IAM-MFA',
    ksi_name: 'Phishing-resistant MFA',
    ksi_statement: 'Enforce MFA.',
    scope: 'CLOUD',
    frmr_version: 'test',
    run_id: 'run-1',
    collected_at: '2026-07-07T00:00:00.000Z',
    category: 'ksi-indicator',
    family: 'IAM',
    impact_level: 'moderate',
    nist_controls: ['ia-2'],
    providers: [
      {
        provider: 'aws',
        findings: [
          {
            rule: 'aws.iam.root_mfa_enabled',
            passed: false,
            severity: 'critical',
            current_state: { summary: 'Root has no MFA', observations: {} },
            target_state: { summary: 'Root MFA on', rationale: 'IA-2(1)' },
            nist_controls: ['ia-2.1'],
            gap: {
              description: 'Root account lacks MFA',
              affected_resources: [{ type: 'aws_account', identifier: '111122223333', name: 'root' }],
            },
          },
        ],
        evidence: [],
      },
    ],
    rollup: { pass: false, passing_findings: 0, failing_findings: 1, warnings: [], missing_evidence: [], alternatives_in_play: 0 },
  };
}

/** Write a full synthetic run dir to a temp location; returns its path. */
export function writeSampleRun(): string {
  const dir = mkdtempSync(join(tmpdir(), 'fedpy-export-'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'inventory.json'), JSON.stringify(sampleSnapshot(), null, 2));
  writeFileSync(join(dir, 'KSI-CNA-ENC.json'), JSON.stringify(sampleKsiEncryption(), null, 2));
  writeFileSync(join(dir, 'VDR-FRP-CAP.json'), JSON.stringify(sampleAwarenessFrr(), null, 2));
  writeFileSync(join(dir, 'service-availability.json'), JSON.stringify({ services: [
    { service: 'AWS Config', status: 'ENABLED', impact: 'All-resource-type discovery breadth.', detail: 'Recorder is recording.' },
    { service: 'Amazon Inspector v2', status: 'DISABLED', impact: 'Vuln Scan columns + CNAPP lever.', detail: 'Account status DISABLED — enable to populate.' },
    { service: 'Amazon Macie', status: 'NOT_AVAILABLE', impact: 'Data Classification column.', detail: 'No service endpoint in this partition/region.' },
  ] }, null, 2));
  // A non-evidence file that must be ignored by the loader.
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ files: [] }));
  return dir;
}
