/**
 * Column metadata for the inventory sheets — the single source that drives
 * display width, text wrapping, inline RISK highlighting, and the Data
 * Dictionary sheet (so the three never drift, the way the PCI tool derives
 * everything from its COLUMNS contract).
 *
 * `risk` is a predicate on the rendered cell string: when it returns true the
 * cell is painted (red = clear gap, amber = attention). Only columns that carry
 * a control signal have a risk rule; identity/metadata columns don't.
 */

export type RiskTone = 'red' | 'amber';

export interface ColumnMeta {
  /** Exact header text used in the inventory tables. */
  title: string;
  /** Display width in Excel "characters". */
  width: number;
  /** Wrap long free text. */
  wrap?: boolean;
  /** Risk predicate + tone (paints the specific cell). */
  risk?: { tone: RiskTone; when: (v: string) => boolean };
  /** Plain-English definition for the Data Dictionary. */
  def: string;
  /** Where the value comes from. */
  source: string;
}

const yes = (v: string) => v.trim().toLowerCase() === 'yes';
const no = (v: string) => v.trim().toLowerCase() === 'no';
const nonEmpty = (v: string) => v.trim() !== '';
const lowTls = (v: string) => /^(ssl|tls\s*v?1(\.[01])?)\b/i.test(v.trim()) || /tlsv1(\.0|\.1)?$/i.test(v.trim());

/**
 * Metadata keyed by column title. Columns not listed here get sensible defaults
 * (width 18, no wrap, no risk) — so adding a CloudAsset field never breaks the
 * writer; it just renders plainly until given metadata.
 */
export const COLUMN_META: Record<string, ColumnMeta> = {
  'Family': { title: 'Family', width: 16, def: 'Resource family grouping (Compute, Storage, Database, …).', source: 'derived from resource type' },
  'Cluster / Grouping': { title: 'Cluster / Grouping', width: 26, def: 'Owning EKS/K8s cluster, VPC, or "account-wide" — where the asset lives / flows from.', source: 'cluster tags → VPC id → account' },
  'Attribution Basis': { title: 'Attribution Basis', width: 16, def: 'How the Cluster/Grouping was derived (eks-cluster-tag / eks-cluster-name / vpc / account-wide).', source: 'attribution logic' },
  'Account/Project/Subscription': { title: 'Account/Project/Subscription', width: 20, def: 'Owning AWS account / GCP project / Azure subscription id.', source: 'collector' },
  'Location': { title: 'Location', width: 16, def: 'Region / availability zone / "global".', source: 'collector' },
  'Resource Type': { title: 'Resource Type', width: 30, def: 'Provider-native resource type (e.g. AWS::S3::Bucket).', source: 'Config / collector' },
  'Asset Type': { title: 'Asset Type', width: 20, def: 'Friendly asset category.', source: 'collector' },
  'Function': { title: 'Function', width: 26, wrap: true, def: 'Resource name or the function it serves.', source: 'Name tag / resource name' },
  'Name/Diagram Label': { title: 'Name/Diagram Label', width: 26, wrap: true, def: 'Diagram-friendly label for architecture docs.', source: 'synthesized / tag' },
  'Unique Asset Identifier': { title: 'Unique Asset Identifier', width: 54, wrap: true, def: 'Stable id — ARN / self-link / resource id. Partition-correct (aws-us-gov in GovCloud).', source: 'collector' },
  'Provider': { title: 'Provider', width: 10, def: 'Cloud provider (aws / gcp / azure).', source: 'collector' },
  'State': { title: 'State', width: 14, def: 'Lifecycle state (running / available / …).', source: 'collector' },
  'Public Facing': { title: 'Public Facing', width: 13, risk: { tone: 'red', when: yes }, def: 'Internet-facing / outside the boundary. Yes is highlighted.', source: 'public IP / scheme / PAB' },
  'IP Addresses': { title: 'IP Addresses', width: 22, wrap: true, def: 'Private + public IPs.', source: 'ENI / endpoint' },
  'DNS Name': { title: 'DNS Name', width: 30, wrap: true, def: 'DNS name / endpoint / URL.', source: 'collector' },
  'Open Ports': { title: 'Open Ports', width: 22, wrap: true, risk: { tone: 'amber', when: nonEmpty }, def: 'Ports/ranges open to the internet (0.0.0.0/0). Any value is highlighted.', source: 'security-group analysis' },
  'VLAN/Network ID': { title: 'VLAN/Network ID', width: 24, def: 'VPC / subnet / network id.', source: 'collector' },
  'OS Name & Version': { title: 'OS Name & Version', width: 22, def: 'Guest OS name + version (hosts only).', source: 'SSM Inventory / OS Config' },
  'Software/DB Name & Version': { title: 'Software/DB Name & Version', width: 26, wrap: true, def: 'Engine / runtime + version (DBs, Lambda, EKS).', source: 'collector' },
  'Software/DB Vendor': { title: 'Software/DB Vendor', width: 16, def: 'Engine vendor.', source: 'collector' },
  'Patch Level': { title: 'Patch Level', width: 22, wrap: true, risk: { tone: 'red', when: (v) => /missing|failed|non.?compliant/i.test(v) }, def: 'Patch compliance summary (hosts). Missing/failed is highlighted.', source: 'SSM Patch Manager' },
  'Baseline Config': { title: 'Baseline Config', width: 18, def: 'Applied hardening baseline (STIG/CIS).', source: 'tag' },
  'Hardware Make/Model': { title: 'Hardware Make/Model', width: 20, def: 'Instance type / class / SKU.', source: 'collector' },
  'vCPU': { title: 'vCPU', width: 8, def: 'Virtual CPU count.', source: 'collector' },
  'Memory (MB)': { title: 'Memory (MB)', width: 12, def: 'Memory in MB.', source: 'collector' },
  'Size (GB)': { title: 'Size (GB)', width: 10, def: 'Storage size in GB.', source: 'collector' },
  'Architecture': { title: 'Architecture', width: 12, def: 'CPU architecture.', source: 'collector' },
  'Image ID': { title: 'Image ID', width: 24, def: 'AMI / image id.', source: 'collector' },
  'K8s Cluster': { title: 'K8s Cluster', width: 20, def: 'Owning EKS/Kubernetes cluster (worker nodes).', source: 'cluster tags' },
  'Node Pool/Group': { title: 'Node Pool/Group', width: 24, def: 'EKS managed node group or Karpenter node pool.', source: 'instance tags' },
  'Node OS Family': { title: 'Node OS Family', width: 18, def: 'Container-host OS (Bottlerocket / AL2 / …) — drives Defender mode.', source: 'SSM / AMI' },
  'FIPS Tagged': { title: 'FIPS Tagged', width: 12, def: 'Operator FIPSCompliant tag on the node.', source: 'tag' },
  'Encryption In Transit': { title: 'Encryption In Transit', width: 14, risk: { tone: 'red', when: no }, def: 'TLS enforced in transit. No is highlighted.', source: 'collector' },
  'TLS Policy': { title: 'TLS Policy', width: 34, wrap: true, def: 'Applied TLS/SSL security policy (ELB).', source: 'elbv2:DescribeListeners' },
  'FIPS TLS': { title: 'FIPS TLS', width: 10, risk: { tone: 'amber', when: no }, def: 'TLS policy is a FIPS policy (-FIPS-). No warrants review.', source: 'derived' },
  'KMS Multi-Region': { title: 'KMS Multi-Region', width: 14, def: 'KMS key is multi-region (mrk-) — DR relevant.', source: 'KMS' },
  'CMVP Validation': { title: 'CMVP Validation', width: 40, wrap: true, def: 'FIPS 140-2/3 CMVP validation note for the protecting module.', source: 'UCM reference' },
  'Encryption At Rest': { title: 'Encryption At Rest', width: 13, risk: { tone: 'red', when: no }, def: 'Encrypted at rest. No is highlighted.', source: 'collector' },
  'KMS Key': { title: 'KMS Key', width: 30, wrap: true, def: 'KMS key id/ARN protecting the resource.', source: 'collector' },
  'Data Classification': { title: 'Data Classification', width: 18, def: 'Sensitivity label (e.g. Macie-flagged).', source: 'Macie / tag' },
  'Authenticated Scan': { title: 'Authenticated Scan', width: 13, def: 'Covered by an authenticated (agent) scan.', source: 'Inspector / VDR' },
  'In Latest Scan': { title: 'In Latest Scan', width: 12, def: 'Present in the most recent vuln scan.', source: 'Inspector / VDR' },
  'Environment': { title: 'Environment', width: 12, def: 'prod / nonprod tag.', source: 'tag' },
  'Criticality': { title: 'Criticality', width: 12, def: 'Business criticality tag.', source: 'tag' },
  'Cost Center': { title: 'Cost Center', width: 14, def: 'Cost-center / billing tag.', source: 'tag' },
  'Application': { title: 'Application', width: 16, def: 'Owning application/service tag.', source: 'tag' },
  'System Owner': { title: 'System Owner', width: 16, def: 'Owning team/person.', source: 'tag' },
  'Application Owner': { title: 'Application Owner', width: 16, def: 'Application owner.', source: 'tag' },
  'Missing Required Tags': { title: 'Missing Required Tags', width: 24, wrap: true, risk: { tone: 'amber', when: nonEmpty }, def: 'Required tags absent on this asset. Any value is highlighted.', source: 'tag governance' },
  'Monthly Cost Est ($)': { title: 'Monthly Cost Est ($)', width: 14, def: 'Month-to-date cost estimate.', source: 'Cost Explorer' },
  'Pricing Model': { title: 'Pricing Model', width: 14, def: 'On-demand / reserved / spot.', source: 'collector' },
  'Created At': { title: 'Created At', width: 20, def: 'Creation timestamp.', source: 'collector' },
  'Last Modified At': { title: 'Last Modified At', width: 20, def: 'Last modification timestamp.', source: 'collector' },
  'Last Used At': { title: 'Last Used At', width: 20, def: 'Last activity/use timestamp.', source: 'collector' },
  'End-of-Life': { title: 'End-of-Life', width: 14, risk: { tone: 'amber', when: nonEmpty }, def: 'Known EOL/EOS date for the runtime/engine/OS. Any value warrants review.', source: 'derived (EOL map)' },
  'Source API': { title: 'Source API', width: 22, def: 'Which collector/API produced this asset.', source: 'collector' },
  'Collected At': { title: 'Collected At', width: 20, def: 'Collection timestamp.', source: 'collector' },
  'Comments': { title: 'Comments', width: 40, wrap: true, def: 'Collector notes / operator comments.', source: 'collector / tag' },
  // Identity/crypto typed fields (from the extra collector).
  'Access Key Age (days)': { title: 'Access Key Age (days)', width: 14, risk: { tone: 'red', when: (v) => Number(v) > 90 }, def: 'Age of the oldest active access key (IAM users). >90d is highlighted.', source: 'credential report' },
  'MFA Enabled': { title: 'MFA Enabled', width: 12, risk: { tone: 'red', when: no }, def: 'MFA active for the principal. No is highlighted.', source: 'IAM' },
  // Service Availability sheet.
  'Service': { title: 'Service', width: 26, def: 'Detective/data service probed for availability.', source: 'service-availability.json' },
  'Impact on Report': { title: 'Impact on Report', width: 44, wrap: true, def: 'What the report loses when this service is not ENABLED.', source: 'probe' },
  'Detail': { title: 'Detail', width: 52, wrap: true, def: 'Probe outcome — recording state, error class, or note.', source: 'probe' },
  // KSI Coverage Matrix + Manual Obligations sheets.
  'Assessment Type': { title: 'Assessment Type', width: 24, def: 'How the KSI is evidenced: Automated (cloud config) / Hybrid (config + process) / Documentation Required / External.', source: 'FRMR scope + actor' },
  'Coverage Status': { title: 'Coverage Status', width: 22, def: 'Live status: config verdict for automated/hybrid; manual-evidence label for documentation/external (never a misleading not-met).', source: 'derived' },
  'KSI ID': { title: 'KSI ID', width: 14, def: 'FedRAMP 20x Key Security Indicator id.', source: 'FRMR catalog' },
  'KSI Name': { title: 'KSI Name', width: 34, wrap: true, def: 'KSI short name.', source: 'FRMR catalog' },
  'What This Report Proves': { title: 'What This Report Proves', width: 46, wrap: true, def: 'What the automated cloud-config evidence establishes for this KSI.', source: 'derived from findings' },
  'What Still Needs Manual Evidence': { title: 'What Still Needs Manual Evidence', width: 46, wrap: true, def: 'What a human/document must supply to fully close the KSI.', source: 'derived' },
  'Artifact / Evidence Owed': { title: 'Artifact / Evidence Owed', width: 48, wrap: true, def: 'The named FedRAMP artifact or record the provider must produce.', source: 'FRMR KSI + FedRAMP process' },
  'Why Not Automatable': { title: 'Why Not Automatable', width: 50, wrap: true, def: 'Why cloud configuration cannot fully evidence this requirement.', source: 'derived' },
  'Class': { title: 'Class', width: 8, def: 'KSI (headline Key Security Indicator) or FRR (supporting FedRAMP requirement).', source: 'FRMR catalog' },
};

export type StatusTone = 'red' | 'amber' | 'good' | 'grey';

/** Compliance/finding columns that carry a status word to colour (full palette). */
export const STATUS_RISK: Record<string, (v: string) => StatusTone | null> = {
  'Compliance Status': (v) => v === 'non-compliant' ? 'red' : v === 'compliant' ? 'good' : v === 'not-assessed' ? 'grey' : null,
  'Status': (v) => (v === 'not-met' || v === 'not-satisfied' || v === 'FAIL' || v === 'ACCESS_DENIED') ? 'red'
    : (v === 'partially-met' || v === 'partially-satisfied' || v === 'VERIFY' || v === 'DISABLED') ? 'amber'
    : (v === 'met' || v === 'satisfied' || v === 'PASS' || v === 'ENABLED') ? 'good'
    : (v === 'not-assessed' || v === 'awareness' || v === 'N/A' || v === 'NOT_AVAILABLE' || v === 'UNKNOWN') ? 'grey' : null,
  'Result': (v) => v === 'FAIL' ? 'red' : v === 'PASS' ? 'good' : null,
  // KSI Coverage Matrix — config verdicts colour like findings; manual/external
  // are grey (informational, not a misconfiguration).
  'Coverage Status': (v) => (v === 'Not Met (Config)' || v === 'Not Assessed') ? 'red'
    : (v === 'Partially Met (Config)' || v === 'Documentation Required') ? 'amber'
    : v === 'Met (Config)' ? 'good'
    : v === 'External / Awareness' ? 'grey' : null,
  // Assessment type: automated (good) / hybrid (amber) / documentation+external (grey).
  'Assessment Type': (v) => v.startsWith('Automated') ? 'good'
    : v.startsWith('Hybrid') ? 'amber'
    : (v.startsWith('Documentation') || v.startsWith('External')) ? 'grey' : null,
  'Priority': (v) => (v.startsWith('P1') || v.startsWith('P2')) ? 'red' : v.startsWith('P3') ? 'amber' : v ? 'grey' : null,
  'Worst Severity': (v) => (v === 'critical' || v === 'high') ? 'red' : v === 'medium' ? 'amber' : v ? 'grey' : null,
  'Severity': (v) => (v === 'critical' || v === 'high') ? 'red' : v === 'medium' ? 'amber' : v ? 'grey' : null,
};

export function columnWidth(title: string): number {
  return COLUMN_META[title]?.width ?? Math.min(Math.max(title.length + 2, 10), 30);
}
export function columnWrap(title: string): boolean {
  return COLUMN_META[title]?.wrap ?? false;
}
export function columnRisk(title: string): ColumnMeta['risk'] | undefined {
  return COLUMN_META[title]?.risk;
}
export { lowTls };
