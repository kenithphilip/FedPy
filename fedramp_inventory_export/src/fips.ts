/**
 * FIPS / Encryption Posture model — the GovCloud crypto lens (SC-13/8/12/28).
 *
 * Answers the question a FedRAMP-High / GovCloud reviewer asks: "is every data
 * store encrypted with a FIPS-validated module, at rest and in transit, and are
 * keys FIPS-validated HSMs?" Built entirely from CloudAsset fields the collectors
 * already produce (encryptionAtRest, kmsKeyId, kmsRotationEnabled, tlsPolicy /
 * fipsTlsPolicy, kmsMultiRegion, cmvpValidation) — no new cloud calls.
 *
 * Pure + deterministic. Modeled on a real GovCloud FIPS-posture analysis.
 */
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { ReportTable } from './tables.ts';

/** Resource types that STORE data and therefore must be encrypted at rest (SC-28). */
const DATA_AT_REST_TYPES: Array<{ match: RegExp; service: string }> = [
  { match: /EC2::Volume/, service: 'EBS Volumes' },
  { match: /EC2::Snapshot/, service: 'EBS Snapshots' },
  { match: /S3::Bucket/, service: 'S3 Buckets' },
  { match: /RDS::DBInstance/, service: 'RDS Instances' },
  { match: /RDS::DBCluster/, service: 'RDS Clusters' },
  { match: /RDS::DBSnapshot/, service: 'RDS Snapshots' },
  { match: /DynamoDB::Table/, service: 'DynamoDB Tables' },
  { match: /ElastiCache/, service: 'ElastiCache' },
  { match: /ECR::Repository/, service: 'ECR Repositories' },
  { match: /EFS::FileSystem/, service: 'EFS File Systems' },
  { match: /Redshift/, service: 'Redshift' },
  { match: /SecretsManager::Secret/, service: 'Secrets Manager' },
  { match: /EKS::Cluster/, service: 'EKS (secrets)' },
];

function serviceFor(a: CloudAsset): string | null {
  const rt = a.resourceType ?? '';
  for (const { match, service } of DATA_AT_REST_TYPES) if (match.test(rt)) return service;
  return null;
}

export type FipsStatus = 'PASS' | 'FAIL' | 'VERIFY' | 'N/A';

// --------------------------------------------------------------------------- #
// 1. Per-service encryption rollup
// --------------------------------------------------------------------------- #

const SERVICE_ROLLUP_COLUMNS = [
  'Service', 'Total', 'Encrypted', 'Unencrypted', 'Unknown', '% Encrypted',
  'KMS-Backed', 'FIPS Validated', 'Status', 'Notes',
] as const;

interface SvcAgg { total: number; enc: number; unenc: number; unknown: number; kms: number; fips: number; }

export function serviceRollupTable(assets: CloudAsset[]): ReportTable {
  const by = new Map<string, SvcAgg>();
  for (const a of assets) {
    const svc = serviceFor(a);
    if (!svc) continue;
    let g = by.get(svc);
    if (!g) { g = { total: 0, enc: 0, unenc: 0, unknown: 0, kms: 0, fips: 0 }; by.set(svc, g); }
    g.total++;
    if (a.encryptionAtRest === true) g.enc++;
    else if (a.encryptionAtRest === false) g.unenc++;
    else g.unknown++;
    if (a.kmsKeyId) g.kms++;
    if (a.cmvpValidation || a.fipsTlsPolicy) g.fips++;
  }
  const rows = [...by.entries()]
    .sort((a, b) => b[1].unenc - a[1].unenc || b[1].unknown - a[1].unknown || a[0].localeCompare(b[0]))
    .map(([svc, g]) => {
      const pct = g.total ? Math.round((g.enc / g.total) * 100) : 0;
      const status: FipsStatus = g.unenc > 0 ? 'FAIL' : g.unknown > 0 ? 'VERIFY' : g.total === 0 ? 'N/A' : 'PASS';
      const notes = g.unenc > 0 ? `${g.unenc} unencrypted — SC-28 gap`
        : g.unknown > 0 ? `${g.unknown} encryption status not read (grant Get*Encryption / enable Config)`
        : g.kms >= g.total ? 'KMS-backed (FIPS HSM in GovCloud)' : 'Encrypted';
      return {
        'Service': svc,
        'Total': String(g.total),
        'Encrypted': String(g.enc),
        'Unencrypted': String(g.unenc),
        'Unknown': String(g.unknown),
        '% Encrypted': `${pct}%`,
        'KMS-Backed': String(g.kms),
        'FIPS Validated': g.fips >= g.total && g.total > 0 ? 'Yes' : g.fips > 0 ? 'Partial' : (g.kms > 0 ? 'KMS (GovCloud HSM)' : 'Verify'),
        'Status': status,
        'Notes': notes,
      };
    });
  return { name: 'fips_service_rollup', title: 'FIPS: Encryption by Service', columns: [...SERVICE_ROLLUP_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// 2. Encryption-gap list (every unencrypted / unknown data-store asset)
// --------------------------------------------------------------------------- #

const GAP_COLUMNS = [
  'Status', 'Service', 'Resource Type', 'Resource', 'Cluster / Grouping',
  'Location', 'Encryption At Rest', 'KMS Key', 'Control', 'Action',
] as const;

export function encryptionGapTable(assets: CloudAsset[], attributeGroup: (a: CloudAsset) => string): ReportTable {
  const rows = assets
    .filter((a) => serviceFor(a) && a.encryptionAtRest !== true)
    .map((a) => {
      const unknown = a.encryptionAtRest == null;
      return {
        _rank: unknown ? 1 : 0,
        row: {
          'Status': unknown ? 'VERIFY' : 'FAIL',
          'Service': serviceFor(a)!,
          'Resource Type': a.resourceType ?? '',
          'Resource': a.function ?? a.uniqueId,
          'Cluster / Grouping': attributeGroup(a),
          'Location': a.location ?? '',
          'Encryption At Rest': a.encryptionAtRest === false ? 'No' : 'Unknown',
          'KMS Key': a.kmsKeyId ?? '',
          'Control': 'SC-28',
          'Action': unknown
            ? 'Read bucket/table encryption config (Get*Encryption) or enable AWS Config to confirm.'
            : 'Enable KMS encryption at rest (SSE-KMS) before authorization.',
        },
      };
    })
    .sort((a, b) => a._rank - b._rank || a.row['Service'].localeCompare(b.row['Service']) || a.row['Resource'].localeCompare(b.row['Resource']))
    .map((x) => x.row);
  return { name: 'fips_encryption_gaps', title: 'FIPS: Encryption Gaps', columns: [...GAP_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// 3. KMS key register (multi-region + rotation + CMVP)
// --------------------------------------------------------------------------- #

const KMS_COLUMNS = [
  'Key', 'Location', 'Multi-Region', 'Rotation Enabled', 'FIPS / CMVP', 'State', 'Notes',
] as const;

export function kmsRegisterTable(assets: CloudAsset[]): ReportTable {
  const rows = assets
    .filter((a) => (a.resourceType ?? '') === 'AWS::KMS::Key')
    .map((a) => ({
      'Key': a.function ?? a.uniqueId,
      'Location': a.location ?? '',
      'Multi-Region': a.kmsMultiRegion === true ? 'Yes' : a.kmsMultiRegion === false ? 'No' : '',
      'Rotation Enabled': a.kmsRotationEnabled === true ? 'Yes' : a.kmsRotationEnabled === false ? 'No' : 'Unknown',
      'FIPS / CMVP': a.cmvpValidation ?? '',
      'State': a.state ?? '',
      'Notes': a.comments ?? '',
    }))
    .sort((a, b) => a['Key'].localeCompare(b['Key']));
  return { name: 'fips_kms_register', title: 'FIPS: KMS Key Register', columns: [...KMS_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// 4. Crypto control rollup (SC-13/8/12/28) + FIPS endpoint note
// --------------------------------------------------------------------------- #

const CONTROL_COLUMNS = ['Control', 'Name', 'Status', 'What We Observed', 'Gaps / Not Collectable'] as const;

export function cryptoControlTable(assets: CloudAsset[]): ReportTable {
  const dataStores = assets.filter((a) => serviceFor(a));
  const unenc = dataStores.filter((a) => a.encryptionAtRest === false).length;
  const unknown = dataStores.filter((a) => a.encryptionAtRest == null).length;
  const tlsAssets = assets.filter((a) => a.tlsPolicy);
  const nonFipsTls = tlsAssets.filter((a) => a.fipsTlsPolicy === false).length;
  const kmsKeys = assets.filter((a) => (a.resourceType ?? '') === 'AWS::KMS::Key');
  const noRotation = kmsKeys.filter((a) => a.kmsRotationEnabled === false).length;

  const restStatus: FipsStatus = unenc > 0 ? 'FAIL' : unknown > 0 ? 'VERIFY' : 'PASS';
  const transitStatus: FipsStatus = nonFipsTls > 0 ? 'FAIL' : tlsAssets.length ? 'PASS' : 'VERIFY';

  const rows = [
    {
      'Control': 'SC-13', 'Name': 'Cryptographic Protection',
      'Status': restStatus === 'PASS' && transitStatus === 'PASS' ? 'PASS' : 'VERIFY',
      'What We Observed': `${dataStores.length - unenc - unknown}/${dataStores.length} data stores encrypted with FIPS-validated modules (GovCloud KMS = FIPS 140-2/3 HSM).`,
      'Gaps / Not Collectable': unenc > 0 || unknown > 0 ? `${unenc} unencrypted, ${unknown} unverified.` : 'None from cloud config.',
    },
    {
      'Control': 'SC-8', 'Name': 'Transmission Confidentiality & Integrity',
      'Status': transitStatus,
      'What We Observed': `${tlsAssets.length} TLS-terminating endpoint(s); ${tlsAssets.filter((a) => a.fipsTlsPolicy).length} on a FIPS TLS policy.`,
      'Gaps / Not Collectable': `${nonFipsTls} non-FIPS TLS policy. Per-app FIPS endpoint usage (s3-fips.*) is NOT_COLLECTABLE — verify in app/SDK config (AWS_USE_FIPS_ENDPOINT=true).`,
    },
    {
      'Control': 'SC-12', 'Name': 'Key Establishment & Management',
      'Status': noRotation > 0 ? 'VERIFY' : kmsKeys.length ? 'PASS' : 'VERIFY',
      'What We Observed': `${kmsKeys.length} KMS key(s); ${kmsKeys.filter((a) => a.kmsMultiRegion).length} multi-region (DR); FIPS 140-2 Level 3 HSMs.`,
      'Gaps / Not Collectable': noRotation > 0 ? `${noRotation} key(s) without automatic rotation.` : 'Rotation status unread on some keys if access-limited.',
    },
    {
      'Control': 'SC-28', 'Name': 'Protection of Information at Rest',
      'Status': restStatus,
      'What We Observed': `Encryption-at-rest evaluated across ${dataStores.length} data stores.`,
      'Gaps / Not Collectable': unenc > 0 || unknown > 0 ? `${unenc} unencrypted (fix), ${unknown} unverified (read config / enable Config).` : 'None.',
    },
  ];
  return { name: 'fips_control_rollup', title: 'FIPS: Crypto Controls (SC-13/8/12/28)', columns: [...CONTROL_COLUMNS], rows };
}

/** Build all FIPS posture tables. */
export function buildFipsTables(assets: CloudAsset[], attributeGroup: (a: CloudAsset) => string): ReportTable[] {
  return [
    cryptoControlTable(assets),
    serviceRollupTable(assets),
    encryptionGapTable(assets, attributeGroup),
    kmsRegisterTable(assets),
  ];
}
