/**
 * Turn a JoinResult into fixed-column report tables (one per sheet / CSV).
 *
 * Every table is a `{ columns, rows }` pair with a stable column order and
 * deterministic row order, ready for the CSV / XLSX writers. This is where the
 * "all the info in the export" contract is made explicit: the Full Inventory
 * table surfaces every rich CloudAsset field the collectors populate, and the
 * compliance tables carry the pass/fail standing against Rev5 + 20x Moderate.
 *
 * Pure + deterministic.
 */
import type { CloudAsset } from '../../cloud-evidence/core/inventory-workbook.ts';
import type { ControlBenchmark } from '../../cloud-evidence/core/control-benchmark.ts';
import type {
  JoinResult,
  AssetCompliance,
  RequirementRollup,
  FlatFinding,
} from './join.ts';
import { attributeAsset, ACCOUNT_WIDE, groupRank } from './attribution.ts';
import { LEVERS, LEVER_ORDER, leverForFinding } from './remediation.ts';
import { COLUMN_META } from './columns.ts';
import { buildFipsTables } from './fips.ts';
import { buildNodeTables } from './nodes.ts';

export interface ReportTable {
  /** File base name (CSV) and sheet key. */
  name: string;
  /** Human sheet title (<=31 chars for XLSX). */
  title: string;
  columns: string[];
  rows: Array<Record<string, string>>;
}

// --------------------------------------------------------------------------- #
// Cell helpers
// --------------------------------------------------------------------------- #

/** Sentinel used when a field was not collected (honestly-partial, never faked). */
const NOT_COLLECTED = '';

function s(v: unknown): string {
  if (v == null) return NOT_COLLECTED;
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean).join('; ');
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function tri(v: boolean | null | undefined): string {
  return v === true ? 'Yes' : v === false ? 'No' : '';
}

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

// --------------------------------------------------------------------------- #
// 1. Full Inventory — every rich CloudAsset field
// --------------------------------------------------------------------------- #

const INVENTORY_COLUMNS = [
  // Flow-down keys first: Family -> Cluster/Grouping -> Account -> Resource.
  'Family', 'Cluster / Grouping', 'Attribution Basis',
  'Account/Project/Subscription', 'Location', 'Resource Type', 'Asset Type',
  'Function', 'Name/Diagram Label', 'Unique Asset Identifier', 'Provider', 'State',
  'Public Facing', 'IP Addresses', 'DNS Name', 'Open Ports', 'VLAN/Network ID',
  'OS Name & Version', 'Software/DB Name & Version', 'Software/DB Vendor', 'Patch Level',
  'Baseline Config', 'Hardware Make/Model', 'vCPU', 'Memory (MB)', 'Size (GB)',
  'Architecture', 'Image ID',
  'K8s Cluster', 'Node Pool/Group', 'Node OS Family', 'FIPS Tagged',
  'Encryption At Rest', 'Encryption In Transit', 'TLS Policy', 'FIPS TLS', 'KMS Key',
  'KMS Multi-Region', 'CMVP Validation', 'Data Classification',
  'Authenticated Scan', 'In Latest Scan',
  'Environment', 'Criticality', 'Cost Center', 'Application', 'System Owner',
  'Application Owner', 'Missing Required Tags', 'Monthly Cost Est ($)', 'Pricing Model',
  'Created At', 'Last Modified At', 'Last Used At', 'End-of-Life',
  'Source API', 'Collected At', 'Comments',
] as const;

function inventoryRow(a: CloudAsset): Record<string, string> {
  const attr = attributeAsset(a);
  return {
    'Family': assetFamily(a),
    'Cluster / Grouping': attr.group,
    'Attribution Basis': attr.basis,
    'Unique Asset Identifier': s(a.uniqueId),
    'Provider': s(a.provider),
    'Account/Project/Subscription': s(a.accountId),
    'Resource Type': s(a.resourceType),
    'Asset Type': s(a.assetType),
    'Function': s(a.function),
    'Name/Diagram Label': s(a.diagramLabel),
    'Location': s(a.location),
    'State': s(a.state),
    'Public Facing': tri(a.publicFacing),
    'IP Addresses': s(a.ips),
    'DNS Name': s(a.dns),
    'Open Ports': s(a.openPorts),
    'VLAN/Network ID': s(a.vlanNetworkId),
    'OS Name & Version': s(a.osNameVersion),
    'Software/DB Name & Version': s(a.softwareDatabaseNameVersion),
    'Software/DB Vendor': s(a.softwareDatabaseVendor),
    'Patch Level': s(a.patchLevel),
    'Baseline Config': s(a.baselineConfig),
    'Hardware Make/Model': s(a.hardwareMakeModel),
    'vCPU': s(a.vcpu),
    'Memory (MB)': s(a.memoryMb),
    'Size (GB)': s(a.sizeGb),
    'Architecture': s(a.architecture),
    'Image ID': s(a.imageId),
    'K8s Cluster': s(a.k8sCluster),
    'Node Pool/Group': s(a.nodeGroup ?? a.karpenterNodePool),
    'Node OS Family': s(a.nodeOsFamily),
    'FIPS Tagged': tri(a.fipsTagged),
    'Encryption At Rest': tri(a.encryptionAtRest),
    'Encryption In Transit': tri(a.encryptionInTransit),
    'TLS Policy': s(a.tlsPolicy),
    'FIPS TLS': tri(a.fipsTlsPolicy),
    'KMS Key': s(a.kmsKeyId),
    'KMS Multi-Region': tri(a.kmsMultiRegion),
    'CMVP Validation': s(a.cmvpValidation),
    'Data Classification': s(a.dataClassification),
    'Authenticated Scan': tri(a.authenticatedScan),
    'In Latest Scan': tri(a.inLatestScan),
    'Environment': s(a.environment),
    'Criticality': s(a.criticality),
    'Cost Center': s(a.costCenter),
    'Application': s(a.application),
    'System Owner': s(a.systemOwner),
    'Application Owner': s(a.applicationOwner),
    'Missing Required Tags': s(a.missingRequiredTags),
    'Monthly Cost Est ($)': s(a.monthlyCostEstimate),
    'Pricing Model': s(a.pricingModel),
    'Created At': s(a.createdAt),
    'Last Modified At': s(a.lastModifiedAt),
    'Last Used At': s(a.lastUsedAt),
    'End-of-Life': s(a.endOfLife),
    'Source API': s(a.sourceApi),
    'Collected At': s(a.collectedAt),
    'Comments': s(a.comments),
  };
}

/**
 * Columns always retained even when empty — the flow-down keys + identity that
 * keep every inventory tab recognizable and comparable.
 */
const INVENTORY_KEEP_COLUMNS = new Set<string>([
  'Family', 'Cluster / Grouping', 'Account/Project/Subscription', 'Location',
  'Resource Type', 'Function', 'Unique Asset Identifier',
]);

/**
 * Drop columns that are empty for EVERY row of a table (so a Storage tab doesn't
 * carry always-blank OS/vCPU columns), except those in `keep`. Returns a new
 * table; row objects are shared (the writer only reads listed columns).
 */
function pruneEmptyColumns(table: ReportTable, keep: Set<string>): ReportTable {
  const columns = table.columns.filter((c) =>
    keep.has(c) || table.rows.some((r) => (r[c] ?? '').trim() !== ''),
  );
  return { ...table, columns };
}

function inventoryTable(assets: CloudAsset[]): ReportTable {
  const rows = [...assets]
    .sort((a, b) => a.uniqueId.localeCompare(b.uniqueId))
    .map(inventoryRow);
  // The master sheet keeps the full contract; per-family sheets are pruned.
  return { name: 'full_inventory', title: 'Full Inventory', columns: [...INVENTORY_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// 1b. Resource-family segmentation — one sheet per family (like the PCI tool's
//     per-type reports), so 1000+ assets are navigable instead of one flat list.
// --------------------------------------------------------------------------- #

/**
 * Classify an asset into a coarse resource FAMILY from its provider resource
 * type / assetType. Matched most-specific-first; anything unmatched → 'Other'.
 * These families drive the per-family sheets + the Family Summary counts.
 */
/**
 * Map an AWS resource type to a family. Keys off the resource TYPE (not just the
 * service) so RDS::DBInstance→Database (not Compute) and SecretsManager::Secret→
 * Crypto/Secrets (not Containers). Resolution order:
 *   1. exact per-type overrides (where a service spans families),
 *   2. AWS service namespace (AWS::<Service>::),
 *   3. keyword heuristics (GCP/Azure/other-provider fallback).
 */

/** Service namespace (lowercased) → family. */
const SERVICE_FAMILY: Record<string, string> = {
  ec2: 'Compute', autoscaling: 'Compute', imagebuilder: 'Compute', batch: 'Compute',
  s3: 'Storage', efs: 'Storage', fsx: 'Storage', backup: 'Storage', glacier: 'Storage', storagegateway: 'Storage',
  rds: 'Database', dynamodb: 'Database', elasticache: 'Database', redshift: 'Database',
  docdb: 'Database', neptune: 'Database', memorydb: 'Database', timestream: 'Database',
  cassandra: 'Database', qldb: 'Database', athena: 'Database', rds_snapshot: 'Storage',
  eks: 'Containers', ecs: 'Containers', ecr: 'Containers', apprunner: 'Containers',
  lambda: 'Serverless', stepfunctions: 'Serverless', states: 'Serverless',
  elasticloadbalancingv2: 'Edge/LB/DNS', elasticloadbalancing: 'Edge/LB/DNS',
  cloudfront: 'Edge/LB/DNS', apigateway: 'Edge/LB/DNS', apigatewayv2: 'Edge/LB/DNS',
  route53: 'Edge/LB/DNS', route53resolver: 'Edge/LB/DNS', globalaccelerator: 'Edge/LB/DNS',
  iam: 'IAM/Identity', identitystore: 'IAM/Identity', ssoadmin: 'IAM/Identity', sso: 'IAM/Identity',
  cognito: 'IAM/Identity', 'cognito-idp': 'IAM/Identity', organizations: 'IAM/Identity',
  kms: 'Crypto/Secrets', secretsmanager: 'Crypto/Secrets', acm: 'Crypto/Secrets',
  'acm-pca': 'Crypto/Secrets', signer: 'Crypto/Secrets',
  guardduty: 'Security/Audit', securityhub: 'Security/Audit', inspector: 'Security/Audit',
  inspector2: 'Security/Audit', macie: 'Security/Audit', accessanalyzer: 'Security/Audit',
  detective: 'Security/Audit', shield: 'Security/Audit', wafv2: 'Security/Audit', waf: 'Security/Audit',
  config: 'Security/Audit', cloudtrail: 'Security/Audit', securitylake: 'Security/Audit', auditmanager: 'Security/Audit',
  cloudwatch: 'Monitoring/Messaging', logs: 'Monitoring/Messaging', sns: 'Monitoring/Messaging',
  sqs: 'Monitoring/Messaging', events: 'Monitoring/Messaging', firehose: 'Monitoring/Messaging',
  kinesis: 'Monitoring/Messaging', xray: 'Monitoring/Messaging',
  cloudformation: 'Management/DevOps', ssm: 'Management/DevOps', appconfig: 'Management/DevOps',
  servicecatalog: 'Management/DevOps', codepipeline: 'Management/DevOps', codebuild: 'Management/DevOps',
  codecommit: 'Management/DevOps', codedeploy: 'Management/DevOps',
};

export function assetFamily(a: CloudAsset): string {
  const rt = a.resourceType ?? '';
  if (rt === 'Account') return 'Account';

  // (2) AWS namespace: AWS::<Service>::<Type> — most reliable.
  const m = /^AWS::([^:]+)::/.exec(rt);
  if (m) {
    const svc = m[1]!.toLowerCase();
    // Per-type override: EC2 spans Compute + Network + Storage.
    if (svc === 'ec2') {
      if (/Volume|Snapshot/.test(rt)) return 'Storage';
      if (/Instance|Fleet|LaunchTemplate|Host|CapacityReservation|SpotFleet/.test(rt)) return 'Compute';
      return 'Network'; // VPC, Subnet, SG, ENI, RouteTable, NAT/IGW, EIP, FlowLog, DHCP, ...
    }
    if (svc === 'rds' && /Snapshot/.test(rt)) return 'Storage';
    return SERVICE_FAMILY[svc] ?? 'Other';
  }

  // (3) keyword heuristics for non-AWS providers / free-form assetType.
  const t = `${rt} ${a.assetType ?? ''}`.toLowerCase();
  if (/account/.test(t) && !/accountattribute/.test(t)) return 'Account';
  if (/secret|::key|kms|certificate|\bacm\b/.test(t)) return 'Crypto/Secrets';
  if (/rds|dynamodb|database|sql|elasticache|redshift|spanner|bigtable|firestore|cosmos/.test(t)) return 'Database';
  if (/bucket|storage|volume|disk|filestore|blob/.test(t)) return 'Storage';
  if (/lambda|function|serverless/.test(t)) return 'Serverless';
  if (/eks|gke|aks|kubernetes|cluster|container|registry/.test(t)) return 'Containers';
  if (/loadbalanc|\belb\b|cloudfront|cdn|dns|route53|apigateway/.test(t)) return 'Edge/LB/DNS';
  if (/vpc|subnet|securitygroup|network|firewall|nat|gateway|peering|interface/.test(t)) return 'Network';
  if (/iam|identity|role|policy|user|cognito|principal/.test(t)) return 'IAM/Identity';
  if (/instance|compute|\bvm\b/.test(t)) return 'Compute';
  return 'Other';
}

/** Deterministic family display order (Account first, Other last). */
const FAMILY_ORDER = [
  'Account', 'Compute', 'Storage', 'Database', 'Containers', 'Serverless',
  'Edge/LB/DNS', 'Network', 'IAM/Identity', 'Crypto/Secrets',
  'Security/Audit', 'Monitoring/Messaging', 'Management/DevOps', 'Other',
];
function familyRank(f: string): number {
  const i = FAMILY_ORDER.indexOf(f);
  return i < 0 ? FAMILY_ORDER.length : i;
}

/** Sheet-name-safe slug for a family (used for CSV file base + XLSX tab). */
function familySlug(f: string): string {
  return 'inv_' + f.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

/** One inventory sheet per non-empty family (same 45-column contract). */
function familyInventoryTables(assets: CloudAsset[]): ReportTable[] {
  const byFamily = new Map<string, CloudAsset[]>();
  for (const a of assets) {
    const f = assetFamily(a);
    (byFamily.get(f) ?? byFamily.set(f, []).get(f)!).push(a);
  }
  const families = [...byFamily.keys()].sort((a, b) => familyRank(a) - familyRank(b) || a.localeCompare(b));
  return families.map((f) => {
    const rows = [...byFamily.get(f)!]
      .sort((a, b) => a.uniqueId.localeCompare(b.uniqueId))
      .map(inventoryRow);
    // XLSX sheet titles cap at 31 chars; keep the family readable.
    const full = { name: familySlug(f), title: `Inv: ${f}`.slice(0, 31), columns: [...INVENTORY_COLUMNS], rows };
    // Prune columns that are empty for THIS family so each tab shows only the
    // fields relevant to its resource types (no always-blank OS/vCPU on Storage,
    // no Software/DB on Compute, etc.).
    return pruneEmptyColumns(full, INVENTORY_KEEP_COLUMNS);
  });
}

const FAMILY_SUMMARY_COLUMNS = [
  'Family', 'Asset Count', 'Non-Compliant', 'Compliant', 'Not-Assessed', 'Resource Types',
] as const;

/** Family Summary: counts per family + compliance split (like PCI summary_by_*). */
function familySummaryTable(rows: AssetCompliance[]): ReportTable {
  interface Agg { count: number; nonCompliant: number; compliant: number; notAssessed: number; types: Set<string>; }
  const byFamily = new Map<string, Agg>();
  for (const ac of rows) {
    const f = assetFamily(ac.asset);
    let agg = byFamily.get(f);
    if (!agg) { agg = { count: 0, nonCompliant: 0, compliant: 0, notAssessed: 0, types: new Set() }; byFamily.set(f, agg); }
    agg.count++;
    if (ac.status === 'non-compliant') agg.nonCompliant++;
    else if (ac.status === 'compliant') agg.compliant++;
    else agg.notAssessed++;
    if (ac.asset.resourceType) agg.types.add(ac.asset.resourceType);
  }
  const out = [...byFamily.entries()]
    .sort((a, b) => familyRank(a[0]) - familyRank(b[0]) || a[0].localeCompare(b[0]))
    .map(([f, agg]) => ({
      'Family': f,
      'Asset Count': String(agg.count),
      'Non-Compliant': String(agg.nonCompliant),
      'Compliant': String(agg.compliant),
      'Not-Assessed': String(agg.notAssessed),
      'Resource Types': [...agg.types].sort().join('; '),
    }));
  return { name: 'family_summary', title: 'Family Summary', columns: [...FAMILY_SUMMARY_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 1c. Cluster / Grouping summary — where assets live + flow from (PCI-style).
// --------------------------------------------------------------------------- #

const CLUSTER_SUMMARY_COLUMNS = [
  'Cluster / Grouping', 'Attribution Basis', 'Asset Count',
  'Non-Compliant', 'Compliant', 'Not-Assessed', 'Regions', 'Families',
] as const;

function clusterSummaryTable(rows: AssetCompliance[]): ReportTable {
  interface Agg {
    basis: string; count: number; nonCompliant: number; compliant: number; notAssessed: number;
    regions: Set<string>; families: Set<string>;
  }
  const byGroup = new Map<string, Agg>();
  for (const ac of rows) {
    const attr = attributeAsset(ac.asset);
    let agg = byGroup.get(attr.group);
    if (!agg) { agg = { basis: attr.basis, count: 0, nonCompliant: 0, compliant: 0, notAssessed: 0, regions: new Set(), families: new Set() }; byGroup.set(attr.group, agg); }
    agg.count++;
    if (ac.status === 'non-compliant') agg.nonCompliant++;
    else if (ac.status === 'compliant') agg.compliant++;
    else agg.notAssessed++;
    if (ac.asset.location) agg.regions.add(ac.asset.location);
    agg.families.add(assetFamily(ac.asset));
  }
  const out = [...byGroup.entries()]
    .sort((a, b) => {
      const [ra, ka] = groupRank(a[0]); const [rb, kb] = groupRank(b[0]);
      return ra - rb || b[1].count - a[1].count || ka.localeCompare(kb);
    })
    .map(([group, agg]) => ({
      'Cluster / Grouping': group,
      'Attribution Basis': agg.basis,
      'Asset Count': String(agg.count),
      'Non-Compliant': String(agg.nonCompliant),
      'Compliant': String(agg.compliant),
      'Not-Assessed': String(agg.notAssessed),
      'Regions': [...agg.regions].sort().join('; '),
      'Families': [...agg.families].sort((x, y) => x.localeCompare(y)).join('; '),
    }));
  return { name: 'cluster_summary', title: 'Cluster / Grouping Summary', columns: [...CLUSTER_SUMMARY_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 1d. Remediation Plan — failing findings grouped by SECURITY LEVER (the tool a
//     security-engineering team deploys to close the gap). Deployment-oriented.
// --------------------------------------------------------------------------- #

const REMEDIATION_COLUMNS = [
  'Security Lever', 'Priority', 'Requirement ID', 'Requirement', 'Rule',
  'Affected Assets', 'Affected Scope', 'Action', 'NIST Controls', 'Suggested Owner',
] as const;

const SEV_PRIORITY: Record<string, string> = {
  critical: 'P1 - Critical', high: 'P2 - High', medium: 'P3 - Medium', low: 'P4 - Low', info: 'P5 - Info',
};
const sevRank2: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** One row per failing finding, grouped by lever then severity. Deploy-ready. */
function remediationPlanTable(findings: FlatFinding[]): ReportTable {
  const fails = findings.filter((f) => !f.passed && !f.awarenessOnly);
  const rows = fails
    .map((f) => {
      const leverKey = leverForFinding(f);
      const lever = LEVERS[leverKey]!;
      const scope = f.affectedDisplay || (f.affectedCount > 0 ? `${f.affectedCount} resource(s)` : 'account-wide');
      return {
        _leverKey: leverKey,
        _sev: f.severity,
        row: {
          'Security Lever': lever.name,
          'Priority': SEV_PRIORITY[f.severity] ?? f.severity,
          'Requirement ID': f.requirementId,
          'Requirement': f.requirementName,
          'Rule': f.rule,
          'Affected Assets': f.affectedCount > 0 ? String(f.affectedCount) : (f.affectedDisplay === 'account-wide' ? 'account-wide' : '—'),
          'Affected Scope': scope,
          'Action': f.remediationSummary || f.gapDescription || 'See finding detail.',
          'NIST Controls': f.nistControls.map((c) => c.toUpperCase()).join('; '),
          'Suggested Owner': f.ownerTeam || lever.defaultOwner,
        },
      };
    })
    .sort((a, b) =>
      (LEVER_ORDER.indexOf(a._leverKey) - LEVER_ORDER.indexOf(b._leverKey)) ||
      (sevRank2[a._sev]! - sevRank2[b._sev]!) ||
      a.row['Requirement ID'].localeCompare(b.row['Requirement ID']) ||
      a.row['Rule'].localeCompare(b.row['Rule']),
    )
    .map((x) => x.row);
  return { name: 'remediation_plan', title: 'Remediation Plan', columns: [...REMEDIATION_COLUMNS], rows };
}

/** Lever roll-up: one row per lever with counts by severity (leadership view). */
const LEVER_SUMMARY_COLUMNS = [
  'Security Lever', 'Findings', 'Critical', 'High', 'Medium', 'Low', 'Default Owner',
] as const;

function leverSummaryTable(findings: FlatFinding[]): ReportTable {
  const fails = findings.filter((f) => !f.passed && !f.awarenessOnly);
  interface Agg { total: number; critical: number; high: number; medium: number; low: number; }
  const byLever = new Map<string, Agg>();
  for (const f of fails) {
    const k = leverForFinding(f);
    let a = byLever.get(k);
    if (!a) { a = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }; byLever.set(k, a); }
    a.total++;
    if (f.severity === 'critical') a.critical++;
    else if (f.severity === 'high') a.high++;
    else if (f.severity === 'medium') a.medium++;
    else if (f.severity === 'low') a.low++;
  }
  const out = LEVER_ORDER.filter((k) => byLever.has(k)).map((k) => {
    const a = byLever.get(k)!;
    return {
      'Security Lever': LEVERS[k]!.name,
      'Findings': String(a.total),
      'Critical': String(a.critical),
      'High': String(a.high),
      'Medium': String(a.medium),
      'Low': String(a.low),
      'Default Owner': LEVERS[k]!.defaultOwner,
    };
  });
  return { name: 'lever_summary', title: 'Remediation by Lever', columns: [...LEVER_SUMMARY_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 2. Asset Compliance — each asset's standing against the requirements
// --------------------------------------------------------------------------- #

const ASSET_COMPLIANCE_COLUMNS = [
  'Compliance Status', 'Worst Severity', 'Unique Asset Identifier', 'Provider',
  'Account/Project/Subscription', 'Resource Type', 'Function', 'Location',
  'Public Facing', 'Encryption At Rest', 'Failing Findings', 'Passing Findings',
  'Failing Requirements / Rules', 'Passing Requirements', 'Implicated NIST Controls',
] as const;

const ASSET_STATUS_RANK: Record<string, number> = {
  'non-compliant': 0, 'compliant': 1, 'not-assessed': 2,
};

function assetComplianceTable(rows: AssetCompliance[]): ReportTable {
  const out = [...rows]
    .sort(
      (a, b) =>
        (ASSET_STATUS_RANK[a.status] ?? 9) - (ASSET_STATUS_RANK[b.status] ?? 9) ||
        b.failingCount - a.failingCount ||
        a.asset.uniqueId.localeCompare(b.asset.uniqueId),
    )
    .map((ac) => ({
      'Compliance Status': ac.status,
      'Worst Severity': ac.worstSeverity ?? '',
      'Unique Asset Identifier': s(ac.asset.uniqueId),
      'Provider': s(ac.asset.provider),
      'Account/Project/Subscription': s(ac.asset.accountId),
      'Resource Type': s(ac.asset.resourceType),
      'Function': s(ac.asset.function),
      'Location': s(ac.asset.location),
      'Public Facing': tri(ac.asset.publicFacing),
      'Encryption At Rest': tri(ac.asset.encryptionAtRest),
      'Failing Findings': String(ac.failingCount),
      'Passing Findings': String(ac.passingCount),
      'Failing Requirements / Rules': ac.failingRules.join('; '),
      'Passing Requirements': ac.passingRequirements.join('; '),
      'Implicated NIST Controls': ac.failingControls.join('; '),
    }));
  return { name: 'asset_compliance', title: 'Asset Compliance', columns: [...ASSET_COMPLIANCE_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 2b. KSI Coverage Matrix — every KSI classified by how it is evidenced.
// --------------------------------------------------------------------------- #

const KSI_MATRIX_COLUMNS = [
  'Assessment Type', 'Coverage Status', 'KSI ID', 'KSI Name', 'Family',
  'What This Report Proves', 'What Still Needs Manual Evidence', 'NIST Controls',
] as const;

// Sort so the config-provable rows lead, then hybrid, then manual/external.
const ASSESSMENT_RANK: Record<string, number> = {
  automated: 0, hybrid: 1, documentation: 2, external: 3,
};

/**
 * The "Coverage Status" for the matrix: for automated/hybrid it's the live
 * config verdict; for documentation/external it's a manual-evidence label (never
 * a misleading "not-met", since no config could satisfy them).
 */
function coverageStatus(r: RequirementRollup): string {
  switch (r.assessmentType) {
    case 'documentation': return 'Documentation Required';
    case 'external': return 'External / Awareness';
    default:
      // automated + hybrid reflect the real finding rollup.
      if (r.status === 'not-assessed') return 'Not Assessed';
      if (r.status === 'met') return 'Met (Config)';
      if (r.status === 'not-met') return 'Not Met (Config)';
      if (r.status === 'partially-met') return 'Partially Met (Config)';
      return r.status;
  }
}

/** What the automated evidence in this report actually proves for the KSI. */
function provesText(r: RequirementRollup): string {
  if (r.assessmentType === 'documentation' || r.assessmentType === 'external') {
    return 'Nothing automatable — not observable from cloud configuration.';
  }
  const n = r.passingFindings + r.failingFindings;
  if (n === 0) return 'No automated evidence produced this run (collector emitted no finding).';
  return `${n} config check(s): ${r.passingFindings} passing, ${r.failingFindings} failing.`;
}

/** What still needs a human / document to fully close the KSI. */
function manualText(r: RequirementRollup): string {
  if (r.assessmentType === 'automated') {
    return r.status === 'met' ? '—' : 'Remediate the failing config check(s) above.';
  }
  return r.artifactOwed || 'Documented procedure or review record.';
}

/** One row per KSI-indicator (the 60 FedRAMP 20x KSIs), classified. */
function ksiCoverageMatrixTable(rows: RequirementRollup[]): ReportTable {
  const ksis = rows.filter((r) => r.category === 'ksi-indicator');
  const out = [...ksis]
    .sort(
      (a, b) =>
        (ASSESSMENT_RANK[a.assessmentType] ?? 9) - (ASSESSMENT_RANK[b.assessmentType] ?? 9) ||
        a.requirementId.localeCompare(b.requirementId),
    )
    .map((r) => ({
      'Assessment Type': r.assessmentLabel,
      'Coverage Status': coverageStatus(r),
      'KSI ID': r.requirementId,
      'KSI Name': r.requirementName,
      'Family': r.family ?? '',
      'What This Report Proves': provesText(r),
      'What Still Needs Manual Evidence': manualText(r),
      'NIST Controls': r.nistControls.join('; '),
    }));
  return { name: 'ksi_coverage_matrix', title: 'KSI Coverage Matrix', columns: [...KSI_MATRIX_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 2c. Manual & Documentation Obligations — the KSIs config cannot close.
// --------------------------------------------------------------------------- #

const OBLIGATION_COLUMNS = [
  'Class', 'Assessment Type', 'Requirement ID', 'Requirement Name', 'Family',
  'Artifact / Evidence Owed', 'Why Not Automatable', 'NIST Controls',
] as const;

/**
 * Every requirement whose full satisfaction needs a human-produced artifact:
 * hybrid (config + process), documentation (pure governance), and external
 * (obligates FedRAMP/agency/assessor). This is the manual side of the workbook —
 * what a provider must produce and a 3PAO will ask for, beyond live config.
 */
function obligationsTable(rows: RequirementRollup[]): ReportTable {
  const manual = rows.filter(
    (r) => r.assessmentType === 'hybrid' || r.assessmentType === 'documentation' || r.assessmentType === 'external',
  );
  // KSI-indicators lead (they are the headline FedRAMP 20x obligations), then the
  // supporting FRR requirements; within each, by assessment type then id.
  const isKsi = (r: RequirementRollup) => r.category === 'ksi-indicator';
  const out = [...manual]
    .sort(
      (a, b) =>
        (isKsi(a) ? 0 : 1) - (isKsi(b) ? 0 : 1) ||
        (ASSESSMENT_RANK[a.assessmentType] ?? 9) - (ASSESSMENT_RANK[b.assessmentType] ?? 9) ||
        a.requirementId.localeCompare(b.requirementId),
    )
    .map((r) => ({
      'Class': isKsi(r) ? 'KSI' : 'FRR',
      'Assessment Type': r.assessmentLabel,
      'Requirement ID': r.requirementId,
      'Requirement Name': r.requirementName,
      'Family': r.family ?? '',
      'Artifact / Evidence Owed': r.artifactOwed || 'Documented procedure or review record.',
      'Why Not Automatable': r.assessmentBasis,
      'NIST Controls': r.nistControls.join('; '),
    }));
  // Title kept <=31 chars so Excel doesn't truncate the sheet tab.
  return { name: 'manual_obligations', title: 'Manual & Doc Obligations', columns: [...OBLIGATION_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 3. Requirement Status (Moderate)
// --------------------------------------------------------------------------- #

const REQUIREMENT_COLUMNS = [
  'Status', 'Assessment Type', 'Requirement ID', 'Requirement Name', 'Category', 'Family', 'FedRAMP Scope',
  'Obligation', 'Passing Findings', 'Failing Findings', 'NIST Controls', 'Note',
] as const;

const REQ_STATUS_RANK: Record<string, number> = {
  'not-met': 0, 'partially-met': 1, 'met': 2, 'not-assessed': 3, 'awareness': 4,
};

function requirementTable(rows: RequirementRollup[]): ReportTable {
  const out = [...rows]
    .sort(
      (a, b) =>
        (REQ_STATUS_RANK[a.status] ?? 9) - (REQ_STATUS_RANK[b.status] ?? 9) ||
        a.requirementId.localeCompare(b.requirementId),
    )
    .map((r) => ({
      'Status': r.status,
      'Assessment Type': r.assessmentLabel,
      'Requirement ID': r.requirementId,
      'Requirement Name': r.requirementName,
      'Category': r.category ?? '',
      'Family': r.family ?? '',
      'FedRAMP Scope': r.scope ?? '',
      'Obligation': r.keyWord ?? '',
      'Passing Findings': String(r.passingFindings),
      'Failing Findings': String(r.failingFindings),
      'NIST Controls': r.nistControls.join('; '),
      'Note': r.note,
    }));
  return { name: 'requirement_status', title: 'Requirement Status (Mod)', columns: [...REQUIREMENT_COLUMNS], rows: out };
}

// --------------------------------------------------------------------------- #
// 4. Control benchmark (one table per framing)
// --------------------------------------------------------------------------- #

const CONTROL_COLUMNS = [
  'Status', 'Control ID', 'Control Name', 'Family', 'Addressed By (Requirement/Rule)',
] as const;

const CONTROL_STATUS_RANK: Record<string, number> = {
  'not-satisfied': 0, 'partially-satisfied': 1, 'satisfied': 2, 'not-assessed': 3,
};

function benchmarkTable(b: ControlBenchmark, name: string, title: string): ReportTable {
  const rows = [...b.controls]
    .sort(
      (a, c) =>
        (CONTROL_STATUS_RANK[a.status] ?? 9) - (CONTROL_STATUS_RANK[c.status] ?? 9) ||
        a.id.localeCompare(c.id),
    )
    .map((c) => ({
      'Status': c.status,
      'Control ID': c.id.toUpperCase(),
      'Control Name': c.name ?? '',
      'Family': c.family ?? '',
      'Addressed By (Requirement/Rule)': c.addressed_by
        .map((x) => `${x.requirement_id}/${x.rule}${x.passed ? '' : ' (FAIL)'}${x.awareness_only ? ' (awareness)' : ''}`)
        .join('; '),
    }));
  return { name, title, columns: [...CONTROL_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// 5. Findings (flat) + 6. Gaps (failing findings only)
// --------------------------------------------------------------------------- #

const FINDING_COLUMNS = [
  'Result', 'Severity', 'Requirement ID', 'Requirement Name', 'Family', 'Provider',
  'Rule', 'Obligation', 'NIST Controls', 'Summary', 'Affected Resources',
] as const;

const findingSeverityRank: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

function findingRow(f: FlatFinding): Record<string, string> {
  return {
    'Result': f.passed ? 'PASS' : 'FAIL',
    'Severity': f.severity,
    'Requirement ID': f.requirementId,
    'Requirement Name': f.requirementName,
    'Family': f.family ?? '',
    'Provider': f.provider,
    'Rule': f.rule,
    'Obligation': f.keyWord ?? '',
    'NIST Controls': f.nistControls.join('; '),
    'Summary': f.passed ? f.summary : f.gapDescription || f.summary,
    'Affected Resources': f.affectedDisplay,
  };
}

function findingsTable(findings: FlatFinding[]): ReportTable {
  const rows = [...findings]
    .sort(
      (a, b) =>
        Number(a.passed) - Number(b.passed) ||
        (findingSeverityRank[a.severity] ?? 9) - (findingSeverityRank[b.severity] ?? 9) ||
        a.requirementId.localeCompare(b.requirementId) ||
        a.rule.localeCompare(b.rule),
    )
    .map(findingRow);
  return { name: 'findings', title: 'Findings', columns: [...FINDING_COLUMNS], rows };
}

function gapsTable(findings: FlatFinding[]): ReportTable {
  const rows = findings
    .filter((f) => !f.passed)
    .sort(
      (a, b) =>
        (findingSeverityRank[a.severity] ?? 9) - (findingSeverityRank[b.severity] ?? 9) ||
        a.requirementId.localeCompare(b.requirementId) ||
        a.rule.localeCompare(b.rule),
    )
    .map(findingRow);
  return { name: 'gaps', title: 'Gaps (Failing)', columns: [...FINDING_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// Assemble every table
// --------------------------------------------------------------------------- #

// --------------------------------------------------------------------------- #
// Data Dictionary — every inventory column defined (from COLUMN_META).
// --------------------------------------------------------------------------- #

const DATA_DICT_COLUMNS = ['#', 'Column', 'Definition', 'Source / Derivation', 'Risk-Highlighted'] as const;

function dataDictionaryTable(): ReportTable {
  const rows = [...INVENTORY_COLUMNS].map((title, i) => {
    const m = COLUMN_META[title];
    return {
      '#': String(i + 1),
      'Column': title,
      'Definition': m?.def ?? '',
      'Source / Derivation': m?.source ?? '',
      'Risk-Highlighted': m?.risk ? (m.risk.tone === 'red' ? 'Yes (red)' : 'Yes (amber)') : '',
    };
  });
  return { name: 'data_dictionary', title: 'Data Dictionary', columns: [...DATA_DICT_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// Requirement Coverage — what read-only cloud evidence can/can't prove, by
// FedRAMP family (the FedRAMP analog of PCI's Requirement Coverage tab).
// --------------------------------------------------------------------------- #

const COVERAGE_COLUMNS = ['Domain / Family', 'Coverage', 'Evidenced By (this run)', 'Requirements', 'Met', 'Partial', 'Not-Met', 'Not Collectable Read-Only'] as const;

/** Static per-family coverage narrative — what read-only cloud APIs can prove. */
const FAMILY_COVERAGE: Record<string, { coverage: string; evidence: string; gap: string }> = {
  IAM: { coverage: 'Strong', evidence: 'MFA, access-key age, wildcard/admin policies, permission-set sessions, Access Analyzer, root usage, password policy', gap: 'Business-need justification + periodic access reviews are process.' },
  CNA: { coverage: 'Strong', evidence: 'Public exposure, security groups, IMDSv2, VPC flow logs, Config recorder, Security Hub critical findings, network firewall/WAF', gap: 'Documented rule justifications + 6-monthly reviews are process.' },
  MLA: { coverage: 'Strong', evidence: 'CloudTrail multi-region/validation/insights, log retention, Config, log export to SIEM', gap: 'Daily log review + alert triage workflow are process/tooling.' },
  SVC: { coverage: 'Partial', evidence: 'Inspector/ECR vuln scanning, code signing, secrets management, encryption in transit', gap: 'Secure-SDLC, code review, change approvals are process.' },
  CMT: { coverage: 'Partial', evidence: 'CloudTrail change events, Config drift, log-file validation + object lock', gap: 'Change-management approvals + review cadence are process.' },
  RPL: { coverage: 'Partial', evidence: 'Backup plans, PITR, Multi-AZ, restore-job history', gap: 'Documented RTO/RPO + tested DR plan are process artifacts.' },
  PIY: { coverage: 'Partial', evidence: 'Inventory mechanism (Config/Resource Explorer) presence', gap: 'Inventory completeness attestation is process.' },
  SCR: { coverage: 'Partial', evidence: 'GuardDuty, Inspector, ECR scan-on-push, supply-chain mitigations', gap: 'SBOM governance + vendor risk process are documentation.' },
  INR: { coverage: 'Partial', evidence: 'GuardDuty detectors, alert routing plumbing (EventBridge/SNS)', gap: 'IR plan, runbooks, and tabletop tests are process.' },
  AFR: { coverage: 'Partial', evidence: 'FIPS/CMVP crypto module usage (KMS/ACM/TLS), vuln detection capability', gap: 'Module inventory + POA&M workflow completed with human input.' },
  CED: { coverage: 'Not collectable read-only', evidence: '—', gap: 'Customer-education artifacts are documentation.' },
};

function requirementCoverageTable(rollups: RequirementRollup[]): ReportTable {
  interface Agg { met: number; partial: number; notMet: number; total: number; }
  const byFam = new Map<string, Agg>();
  for (const r of rollups) {
    const fam = (r.family ?? 'OTHER').toUpperCase();
    let a = byFam.get(fam);
    if (!a) { a = { met: 0, partial: 0, notMet: 0, total: 0 }; byFam.set(fam, a); }
    a.total++;
    if (r.status === 'met') a.met++;
    else if (r.status === 'partially-met') a.partial++;
    else if (r.status === 'not-met') a.notMet++;
  }
  const rows = [...byFam.entries()]
    .sort((a, b) => b[1].notMet - a[1].notMet || a[0].localeCompare(b[0]))
    .map(([fam, a]) => {
      const c = FAMILY_COVERAGE[fam];
      return {
        'Domain / Family': fam,
        'Coverage': c?.coverage ?? 'Process / awareness',
        'Evidenced By (this run)': c?.evidence ?? 'Process-artifact requirement (no cloud API).',
        'Requirements': String(a.total),
        'Met': String(a.met),
        'Partial': String(a.partial),
        'Not-Met': String(a.notMet),
        'Not Collectable Read-Only': c?.gap ?? 'Documented artifact + attestation.',
      };
    });
  return { name: 'requirement_coverage', title: 'Requirement Coverage', columns: [...COVERAGE_COLUMNS], rows };
}

// --------------------------------------------------------------------------- #
// Service Availability — why a lens may be empty (disabled / not-in-partition).
// --------------------------------------------------------------------------- #

const SERVICE_AVAIL_COLUMNS = ['Status', 'Service', 'Impact on Report', 'Detail'] as const;

function serviceAvailabilityTable(rows: JoinResult['serviceAvailability']): ReportTable | null {
  if (!rows.length) return null;
  const rank: Record<string, number> = { DISABLED: 0, ACCESS_DENIED: 1, NOT_AVAILABLE: 2, UNKNOWN: 3, ENABLED: 4 };
  const out = [...rows]
    .sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || a.service.localeCompare(b.service))
    .map((r) => ({ 'Status': r.status, 'Service': r.service, 'Impact on Report': r.impact, 'Detail': r.detail }));
  return { name: 'service_availability', title: 'Service Availability', columns: [...SERVICE_AVAIL_COLUMNS], rows: out };
}

export function buildTables(join: JoinResult): ReportTable[] {
  const assets = join.assetCompliance.map((ac) => ac.asset);
  // Ordered top-to-bottom for flow-down reading:
  //   action → where → what → detail.
  // Non-inventory tables: drop any column that is empty for EVERY row (always
  // keeping the first/key column) so no wholly-blank columns reach a reader.
  const trim = (t: ReportTable) => pruneEmptyColumns(t, new Set([t.columns[0] ?? '']));
  const svcAvail = serviceAvailabilityTable(join.serviceAvailability);
  return [
    // 0) Coverage: which detective/data services are on (why lenses may be empty).
    ...(svcAvail ? [trim(svcAvail)] : []),
    // 1) Action: what security engineering should deploy.
    trim(leverSummaryTable(join.findings)),
    trim(remediationPlanTable(join.findings)),
    // 2) Where: how gaps concentrate by family + cluster/grouping.
    trim(familySummaryTable(join.assetCompliance)),
    trim(clusterSummaryTable(join.assetCompliance)),
    // 2b) FIPS / encryption posture (SC-13/8/12/28) — GovCloud crypto lens.
    ...buildFipsTables(assets, (a) => attributeAsset(a).group).map(trim),
    // 2c) Node analysis + Prisma Defender deployment planning (EKS estate).
    ...buildNodeTables(assets).map(trim),
    // 3) Compliance rollups.
    // 3a) The two coverage lenses first: how every KSI is evidenced (config vs
    //     manual), and the explicit list of manual/documentation obligations.
    trim(ksiCoverageMatrixTable(join.requirements)),
    trim(obligationsTable(join.requirements)),
    trim(requirementCoverageTable(join.requirements)),
    trim(requirementTable(join.requirements)),
    trim(benchmarkTable(join.benchmarks.rev5, 'rev5_control_benchmark', 'Rev5 Controls (Mod)')),
    trim(benchmarkTable(join.benchmarks.twentyX, 'twentyx_control_benchmark', '20x Controls (Mod)')),
    // 4) Detail: findings, then full + per-family inventory.
    trim(findingsTable(join.findings)),
    trim(gapsTable(join.findings)),
    trim(assetComplianceTable(join.assetCompliance)),
    // Full Inventory keeps the complete 49-column contract (source of truth);
    // per-family sheets are pruned to only their relevant columns.
    inventoryTable(assets),
    ...familyInventoryTables(assets),
    // 5) Reference.
    dataDictionaryTable(),
  ];
}

export { pct };
