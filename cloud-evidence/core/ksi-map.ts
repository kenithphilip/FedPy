/**
 * Master map of KSIs the collector can produce evidence for.
 * Phase 1 ships with the 7 IAM KSIs only; subsequent phases add more.
 *
 * Module references are tuples of `[providerName, collectorFunctionName]`.
 * The orchestrator looks up the function at runtime by walking the providers map.
 */
import type { KsiScope, EvidenceFile, ProviderBlock } from './envelope.ts';
import type { AwsAuth } from './auth/aws.ts';
import type { K8sAuth } from './auth/k8s.ts';

export interface CollectorContext {
  aws?: {
    account_id?: string | null;
    profile?: string;
    region: string;
    /**
     * Pre-built AwsAuth to use. When set, collectors must NOT call
     * `makeAwsAuth(region)` themselves; using this auth is how the
     * orchestrator fans out across AWS Organizations member accounts
     * (each carries a different STS-assumed-role credential).
     */
    auth?: AwsAuth;
  };
  gcp?: { project_id: string };
  azure?: {
    /** Tenant id (Entra ID); collectors that need it can also read it from whoAmIAzure(). */
    tenant_id?: string | null;
    /** Optional single subscription id for resource-scoped Azure collectors (most IAM/AAD work is tenant-scoped). */
    subscription_id?: string | null;
    /** All configured subscription ids — for Azure Resource Graph collectors that query across the tenant. */
    subscription_ids?: string[];
  };
  k8s?: { context: string; auth?: K8sAuth };
}

/**
 * Each provider-specific collector returns a ProviderBlock (evidence + findings).
 * The orchestrator wires it into the EvidenceFile envelope.
 */
export type ProviderCollector = (ctx: CollectorContext) => Promise<ProviderBlock>;

export interface KsiEntry {
  id: string;
  name: string;
  scope: KsiScope;
  /** Verbatim FRMR statement — embedded into evidence files for LLM context. */
  statement: string;
  /** NIST 800-53 control IDs this KSI traces to (verbatim from FRMR). */
  nist_controls?: string[];
  /** Provider collectors. A KSI may be AWS-only, GCP-only, or both. */
  aws?: ProviderCollector;
  gcp?: ProviderCollector;
  azure?: ProviderCollector;
  /** For HYBRID KSIs, items the human reviewer must still attach in the tracker. */
  process_artifacts_required?: string[];
}

import * as awsIam from '../providers/aws/iam.ts';
import * as gcpIam from '../providers/gcp/iam.ts';
import * as azIam from '../providers/azure/iam.ts';
import * as azLogging from '../providers/azure/logging.ts';
import * as azNetwork from '../providers/azure/network.ts';
import * as azConfig from '../providers/azure/config.ts';
import * as azBackup from '../providers/azure/backup.ts';
import * as azSecrets from '../providers/azure/secrets.ts';
import * as azSupplychain from '../providers/azure/supplychain.ts';
import * as azData from '../providers/azure/data.ts';
import * as awsNetwork from '../providers/aws/network.ts';
import * as gcpNetwork from '../providers/gcp/network.ts';
import * as awsConfig from '../providers/aws/config.ts';
import * as gcpConfig from '../providers/gcp/config.ts';
import * as awsBackup from '../providers/aws/backup.ts';
import * as gcpBackup from '../providers/gcp/backup.ts';
import * as awsLogging from '../providers/aws/logging.ts';
import * as gcpLogging from '../providers/gcp/logging.ts';
import * as awsSupplychain from '../providers/aws/supplychain.ts';
import * as gcpSupplychain from '../providers/gcp/supplychain.ts';
import * as awsSecrets from '../providers/aws/secrets.ts';
import * as gcpSecrets from '../providers/gcp/secrets.ts';
import * as awsData from '../providers/aws/data.ts';
import * as gcpData from '../providers/gcp/data.ts';
import * as awsInventory from '../providers/aws/inventory.ts';
import * as gcpInventory from '../providers/gcp/inventory.ts';
import * as awsCrypto from '../providers/aws/crypto.ts';
import * as gcpCrypto from '../providers/gcp/crypto.ts';
import * as awsHybrids from '../providers/aws/ksi-hybrids.ts';
import * as gcpHybrids from '../providers/gcp/ksi-hybrids.ts';
import * as awsVdrScan from '../providers/aws/vdr-scan.ts';
import * as gcpVdrScan from '../providers/gcp/vdr-scan.ts';

export const KSI_MAP: Record<string, KsiEntry> = {
  'KSI-IAM-AAM': {
    id: 'KSI-IAM-AAM',
    name: 'Automating Account Management',
    scope: 'CLOUD',
    statement: 'Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.',
    nist_controls: ['ac-2.2','ac-2.3','ac-2.13','ac-6.7','ia-4.4','ia-12','ia-12.2','ia-12.3','ia-12.5'],
    aws: awsIam.collectIamAam,
    gcp: gcpIam.collectIamAam,
    azure: azIam.collectIamAam,
  },
  'KSI-IAM-APM': {
    id: 'KSI-IAM-APM',
    name: 'Adopting Passwordless Methods',
    scope: 'CLOUD',
    statement: 'Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA for authentication.',
    nist_controls: ['ia-2','ia-2.1','ia-5','ia-5.1'],
    aws: awsIam.collectIamApm,
    gcp: gcpIam.collectIamApm,
    azure: azIam.collectIamApm,
  },
  'KSI-IAM-ELP': {
    id: 'KSI-IAM-ELP',
    name: 'Ensuring Least Privilege',
    scope: 'CLOUD',
    statement: 'Persistently ensure that identity and access management employs measures to ensure each user or device can only access the resources they need.',
    nist_controls: ['ac-2','ac-6','ac-6.5'],
    aws: awsIam.collectIamElp,
    gcp: gcpIam.collectIamElp,
    azure: azIam.collectIamElp,
  },
  'KSI-IAM-JIT': {
    id: 'KSI-IAM-JIT',
    name: 'Authorizing Just-in-Time',
    scope: 'HYBRID',
    statement: 'Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.',
    nist_controls: ['ac-2','ac-6.7'],
    aws: awsIam.collectIamJit,
    gcp: gcpIam.collectIamJit,
    azure: azIam.collectIamJit,
    process_artifacts_required: [
      '3rd-party JIT tool name + tenant (if used)',
      'sample request/approval audit log (last 30 days)',
    ],
  },
  'KSI-IAM-MFA': {
    id: 'KSI-IAM-MFA',
    name: 'Enforcing Phishing-Resistant MFA',
    scope: 'CLOUD',
    statement: 'Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication.',
    nist_controls: ['ia-2.1','ia-2.2','ia-2.6','ia-2.8'],
    aws: awsIam.collectIamMfa,
    azure: azIam.collectIamMfa,
    gcp: gcpIam.collectIamMfa,
  },
  'KSI-IAM-SNU': {
    id: 'KSI-IAM-SNU',
    name: 'Securing Non-User Authentication',
    scope: 'CLOUD',
    statement: 'Enforce appropriately secure authentication methods for non-user accounts and services.',
    nist_controls: ['ac-2.7','ia-5','ia-9'],
    aws: awsIam.collectIamSnu,
    gcp: gcpIam.collectIamSnu,
    azure: azIam.collectIamSnu,
  },
  'KSI-IAM-SUS': {
    id: 'KSI-IAM-SUS',
    name: 'Responding to Suspicious Activity',
    scope: 'HYBRID',
    statement: 'Automatically disable or otherwise secure accounts with privileged access in response to suspicious activity.',
    nist_controls: ['au-6','ir-4','si-4'],
    aws: awsIam.collectIamSus,
    gcp: gcpIam.collectIamSus,
    azure: azIam.collectIamSus,
    process_artifacts_required: [
      'response runbook URL',
      'record of last simulated suspicious-activity drill',
    ],
  },

  // ---- CNA: Cloud Native Architecture (4 network KSIs registered; DFP/EIS/IBP/OFA pending) ----
  'KSI-CNA-MAT': {
    id: 'KSI-CNA-MAT',
    name: 'Minimizing Attack Surface',
    scope: 'CLOUD',
    statement: 'Persistently ensure machine-based information resources have a minimal attack surface and that lateral movement is minimized if compromised.',
    nist_controls: ['ac-3','ac-4','sc-7','sc-7.5'],
    aws: awsNetwork.collectCnaMat,
    gcp: gcpNetwork.collectCnaMat,
    azure: azNetwork.collectCnaMat,
  },
  'KSI-CNA-RNT': {
    id: 'KSI-CNA-RNT',
    name: 'Restricting Network Traffic',
    scope: 'CLOUD',
    statement: 'Persistently ensure all machine-based information resources are configured to limit inbound and outbound network traffic.',
    nist_controls: ['ac-4','sc-7','sc-7.5'],
    aws: awsNetwork.collectCnaRnt,
    gcp: gcpNetwork.collectCnaRnt,
    azure: azNetwork.collectCnaRnt,
  },
  'KSI-CNA-ULN': {
    id: 'KSI-CNA-ULN',
    name: 'Using Logical Networking',
    scope: 'CLOUD',
    statement: 'Use logical networking and related capabilities to enforce traffic flow controls.',
    nist_controls: ['ac-4','sc-7','sc-32'],
    aws: awsNetwork.collectCnaUln,
    gcp: gcpNetwork.collectCnaUln,
    azure: azNetwork.collectCnaUln,
  },
  'KSI-CNA-RVP': {
    id: 'KSI-CNA-RVP',
    name: 'Reviewing Protections (DoS etc.)',
    scope: 'CLOUD',
    statement: 'Persistently review the effectiveness of protection against denial of service attacks and other unwanted activity.',
    nist_controls: ['sc-5','sc-5.1','sc-5.2'],
    aws: awsNetwork.collectCnaRvp,
    gcp: gcpNetwork.collectCnaRvp,
    azure: azNetwork.collectCnaRvp,
  },
  'KSI-CNA-DFP': {
    id: 'KSI-CNA-DFP',
    name: 'Defining Functionality and Privileges',
    scope: 'CLOUD',
    statement: 'Strictly define the functionality and privileges for infrastructure and services.',
    nist_controls: ['ac-3','ac-6','ac-6.1','cm-7'],
    aws: awsIam.collectCnaDfp,
    gcp: gcpIam.collectCnaDfp,
    azure: azConfig.collectCnaDfp,
  },
  'KSI-CNA-EIS': {
    id: 'KSI-CNA-EIS',
    name: 'Enforcing Intended State',
    scope: 'CLOUD',
    statement: 'Use automated services to persistently assess the security posture of all machine-based information resources and automatically enforce their intended operational state.',
    nist_controls: ['ca-2.1','ca-7.1'],
    aws: awsConfig.collectCnaEis,
    gcp: gcpConfig.collectCnaEis,
    azure: azConfig.collectCnaEis,
  },
  'KSI-CNA-IBP': {
    id: 'KSI-CNA-IBP',
    name: 'Implementing Best Practices',
    scope: 'CLOUD',
    statement: 'Persistently ensure cloud-native machine-based information resources are implemented based on the host provider\'s best practices and documented guidance.',
    nist_controls: ['cm-6','cm-7','sa-8'],
    aws: awsConfig.collectCnaIbp,
    gcp: gcpConfig.collectCnaIbp,
    azure: azConfig.collectCnaIbp,
  },
  'KSI-CNA-OFA': {
    id: 'KSI-CNA-OFA',
    name: 'Optimizing for Availability',
    scope: 'CLOUD',
    statement: 'Appropriately optimize machine-based information resources for high availability and rapid recovery.',
    nist_controls: ['cp-2','cp-7','cp-10'],
    aws: awsBackup.collectCnaOfa,
    gcp: gcpBackup.collectCnaOfa,
    azure: azBackup.collectCnaOfa,
  },

  // ---- MLA: Monitoring, Logging, and Auditing ----
  'KSI-MLA-ALA': {
    id: 'KSI-MLA-ALA',
    name: 'Authorizing Log Access',
    scope: 'CLOUD',
    statement: 'Use a least-privileged, role and attribute-based, and just-in-time access authorization model for access to log data based on organizationally defined data sensitivity.',
    nist_controls: ['si-11','ac-3'],
    aws: awsLogging.collectMlaAla,
    gcp: gcpLogging.collectMlaAla,
    azure: azLogging.collectMlaAla,
  },
  'KSI-MLA-EVC': {
    id: 'KSI-MLA-EVC',
    name: 'Evaluating Configurations',
    scope: 'CLOUD',
    statement: 'Persistently evaluate and test the configuration of machine-based information resources, especially infrastructure as code.',
    nist_controls: ['ca-7','cm-6','cm-7','ra-5'],
    aws: awsLogging.collectMlaEvc,
    gcp: gcpLogging.collectMlaEvc,
    azure: azLogging.collectMlaEvc,
  },
  'KSI-MLA-LET': {
    id: 'KSI-MLA-LET',
    name: 'Logging Event Types',
    scope: 'HYBRID',
    statement: 'Maintain a list of information resources and event types that will be logged, monitored, and audited, then do so.',
    nist_controls: ['au-2','au-3','au-12'],
    aws: awsLogging.collectMlaLet,
    gcp: gcpLogging.collectMlaLet,
    azure: azLogging.collectMlaLet,
    process_artifacts_required: [
      'Documented list of in-scope information resources × event types',
      'SIEM ingestion topology diagram',
    ],
  },
  'KSI-MLA-OSM': {
    id: 'KSI-MLA-OSM',
    name: 'Operating SIEM Capability',
    scope: 'HYBRID',
    statement: 'Operate a Security Information and Event Management (SIEM) or similar system(s) for centralized, tamper-resistent logging of events, activities, and changes.',
    nist_controls: ['au-2','au-6','au-6.1','au-7'],
    aws: awsLogging.collectMlaOsm,
    gcp: gcpLogging.collectMlaOsm,
    azure: azLogging.collectMlaOsm,
    process_artifacts_required: [
      'SIEM vendor + tenant ID',
      'Alert rule count + sample query',
      'Ingestion lag dashboard URL',
    ],
  },
  'KSI-MLA-RVL': {
    id: 'KSI-MLA-RVL',
    name: 'Reviewing Logs',
    scope: 'CLOUD',
    statement: 'Persistently review and audit logs.',
    nist_controls: ['au-6'],
    aws: awsLogging.collectMlaRvl,
    gcp: gcpLogging.collectMlaRvl,
    azure: azLogging.collectMlaRvl,
  },

  // ---- CMT: Change Management ----
  'KSI-CMT-LMC': {
    id: 'KSI-CMT-LMC',
    name: 'Logging Changes',
    scope: 'CLOUD',
    statement: 'Log and monitor modifications to the cloud service offering.',
    nist_controls: ['au-2','au-3','au-12','cm-3.1','cm-5.1'],
    aws: awsLogging.collectCmtLmc,
    gcp: gcpLogging.collectCmtLmc,
    azure: azLogging.collectCmtLmc,
  },
  'KSI-CMT-RMV': {
    id: 'KSI-CMT-RMV',
    name: 'Redeploying vs Modifying',
    scope: 'CLOUD',
    statement: 'Execute changes to machine-based information resources through redeployment of version controlled immutable resources rather than direct modification wherever reasonable.',
    nist_controls: ['cm-2','cm-2.2','cm-3','sa-10'],
    aws: awsSupplychain.collectCmtRmv,
    gcp: gcpSupplychain.collectCmtRmv,
    azure: azSupplychain.collectCmtRmv,
  },
  'KSI-CMT-VTD': {
    id: 'KSI-CMT-VTD',
    name: 'Validating Throughout Deployment',
    scope: 'HYBRID',
    statement: 'Automate persistent testing and validation of changes throughout deployment.',
    nist_controls: ['cm-3.2','cm-4','sa-11','sa-11.1','si-7'],
    aws: awsSupplychain.collectCmtVtd,
    gcp: gcpSupplychain.collectCmtVtd,
    azure: azSupplychain.collectCmtVtd,
    process_artifacts_required: [
      'SAST/SCA tool inventory + versions',
      'Test coverage report',
      'Gate-effectiveness review minutes',
    ],
  },

  // ---- SVC: Service Configuration (Phase 4) ----
  'KSI-SVC-ACM': {
    id: 'KSI-SVC-ACM',
    name: 'Automating Configuration Management',
    scope: 'CLOUD',
    statement: 'Manage configuration of machine-based information resources using automation.',
    nist_controls: ['cm-2','cm-3','cm-6'],
    aws: awsConfig.collectSvcAcm,
    gcp: gcpConfig.collectSvcAcm,
    azure: azConfig.collectSvcAcm,
  },
  'KSI-SVC-ASM': {
    id: 'KSI-SVC-ASM',
    name: 'Automating Secret Management',
    scope: 'CLOUD',
    statement: 'Automate management, protection, and regular rotation of digital keys, certificates, and other secrets.',
    nist_controls: ['ia-5','ia-5.1','sc-12','sc-12.2'],
    aws: awsSecrets.collectSvcAsm,
    gcp: gcpSecrets.collectSvcAsm,
    azure: azSecrets.collectSvcAsm,
  },
  'KSI-SVC-EIS': {
    id: 'KSI-SVC-EIS',
    name: 'Evaluating and Improving Security',
    scope: 'HYBRID',
    statement: 'Implement improvements based on persistent evaluation of information resources for opportunities to improve security.',
    nist_controls: ['ca-7','pm-31'],
    aws: awsConfig.collectSvcEis,
    gcp: gcpConfig.collectSvcEis,
    azure: azConfig.collectSvcEis,
    process_artifacts_required: [
      'Improvement-decision log (baseline changes attributed to findings)',
      'MTTR-by-severity trend report',
    ],
  },
  'KSI-SVC-RUD': {
    id: 'KSI-SVC-RUD',
    name: 'Removing Unwanted Data',
    scope: 'CLOUD',
    statement: 'Remove unwanted federal customer data promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate.',
    nist_controls: ['mp-6','si-12'],
    aws: awsData.collectSvcRud,
    gcp: gcpData.collectSvcRud,
    azure: azData.collectSvcRud,
  },
  'KSI-SVC-SNT': {
    id: 'KSI-SVC-SNT',
    name: 'Securing Network Traffic',
    scope: 'CLOUD',
    statement: 'Encrypt or otherwise secure network traffic.',
    nist_controls: ['sc-8','sc-8.1','sc-13'],
    aws: awsNetwork.collectSvcSnt,
    gcp: gcpNetwork.collectSvcSnt,
    azure: azNetwork.collectSvcSnt,
  },
  'KSI-SVC-VCM': {
    id: 'KSI-SVC-VCM',
    name: 'Validating Communications',
    scope: 'HYBRID',
    statement: 'Persistently validate the authenticity and integrity of communications between machine-based information resources using automation.',
    nist_controls: ['sc-23','si-7.1'],
    aws: awsData.collectSvcVcm,
    gcp: gcpData.collectSvcVcm,
    azure: azData.collectSvcVcm,
    process_artifacts_required: [
      'Service mesh / mTLS deployment manifests (if used)',
      'Sample mTLS-validated traffic capture or service-mesh audit log',
    ],
  },
  'KSI-SVC-VRI': {
    id: 'KSI-SVC-VRI',
    name: 'Validating Resource Integrity',
    scope: 'CLOUD',
    statement: 'Use cryptographic methods to validate the integrity of machine-based information resources.',
    nist_controls: ['si-7','si-7.1','si-7.6'],
    aws: awsData.collectSvcVri,
    gcp: gcpData.collectSvcVri,
    azure: azData.collectSvcVri,
  },

  // ---- Phase 5 ----
  'KSI-RPL-ABO': {
    id: 'KSI-RPL-ABO',
    name: 'Aligning Backups with Objectives',
    scope: 'HYBRID',
    statement: 'Persistently review the alignment of machine-based information resource backups with defined recovery objectives.',
    nist_controls: ['cp-9','cp-9.1','cp-9.8'],
    aws: awsBackup.collectRplAbo,
    gcp: gcpBackup.collectRplAbo,
    azure: azBackup.collectRplAbo,
    process_artifacts_required: ['RPO/RTO document per system', 'Backup-vs-RPO alignment review minutes'],
  },
  'KSI-RPL-TRC': {
    id: 'KSI-RPL-TRC',
    name: 'Testing Recovery Capabilities',
    scope: 'HYBRID',
    statement: 'Persistently test the capability to recover from incidents and contingencies, including alignment with defined recovery objectives.',
    nist_controls: ['cp-4','cp-4.1','cp-10.2'],
    aws: awsBackup.collectRplTrc,
    gcp: gcpBackup.collectRplTrc,
    azure: azBackup.collectRplTrc,
    process_artifacts_required: ['DR test plan', 'Last test AAR', 'Restore-time-vs-RTO comparison'],
  },
  'KSI-PIY-GIV': {
    id: 'KSI-PIY-GIV',
    name: 'Generating Inventories',
    scope: 'CLOUD',
    statement: 'Use authoritative sources to automatically generate real-time inventories of all information resources when needed.',
    nist_controls: ['cm-8','cm-8.1','pm-5'],
    aws: awsInventory.collectPiyGiv,
    gcp: gcpInventory.collectPiyGiv,
  },
  'KSI-SCR-MON': {
    id: 'KSI-SCR-MON',
    name: 'Monitoring Supply Chain Risk',
    scope: 'HYBRID',
    statement: 'Automatically monitor third party software information resources for upstream vulnerabilities using mechanisms that may include contractual notification requirements or active monitoring services.',
    nist_controls: ['sr-3','ra-5'],
    aws: awsSupplychain.collectScrMon,
    gcp: gcpSupplychain.collectScrMon,
    process_artifacts_required: ['Supply-chain monitoring policy', 'Vendor advisory subscription list', 'Severity-SLA matrix'],
  },
  'KSI-INR-RIR': {
    id: 'KSI-INR-RIR',
    name: 'Reviewing Incident Response Procedures',
    scope: 'HYBRID',
    statement: 'Persistently review the effectiveness of documented incident response procedures.',
    nist_controls: ['ir-4','ir-4.1'],
    aws: awsLogging.collectInrRir,
    gcp: gcpLogging.collectInrRir,
    azure: azLogging.collectInrRir,
    process_artifacts_required: ['IR runbook URL', 'Last procedure-review minutes', 'On-call rotation source'],
  },
  // ---- AFR technical pointer: Using Cryptographic Modules (FIPS/CMVP) ----
  // KSI-AFR-UCM points at the UCM process; the crypto collector supplies the
  // automated FIPS/CMVP evidence (KMS/ACM/TLS) that supports it. The detailed
  // UCM-CSX-* FRR requirements are additionally tracked via process attestation.
  'KSI-AFR-UCM': {
    id: 'KSI-AFR-UCM',
    name: 'Using Cryptographic Modules',
    scope: 'HYBRID',
    statement: 'Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations.',
    nist_controls: ['sc-13', 'sc-12', 'sc-8', 'ia-7'],
    aws: awsCrypto.collectUcm,
    gcp: gcpCrypto.collectUcm,
    process_artifacts_required: [
      'CMVP certificate references for each cryptographic module used to protect federal data',
      'Mapping of services (or service groups) → cryptographic modules',
    ],
  },

  // ---- Phase 4: previously-uncovered KSI hybrid indicators ----
  // Each emits a read-only cloud "proxy" signal that the capability exists; the
  // periodic human review is attached as a process artifact.
  'KSI-CMT-RVP': {
    id: 'KSI-CMT-RVP',
    name: 'Reviewing Change Procedures',
    scope: 'HYBRID',
    statement: 'Persistently review the effectiveness of documented change management procedures.',
    nist_controls: ['cm-3', 'cm-3.2', 'cm-3.4', 'cm-5', 'cm-7.1', 'cm-9'],
    aws: awsHybrids.collectCmtRvp,
    gcp: gcpHybrids.collectCmtRvp,
    process_artifacts_required: ['Change-procedure effectiveness review minutes', 'Sample of changes verified against the documented procedure'],
  },
  'KSI-INR-AAR': {
    id: 'KSI-INR-AAR',
    name: 'Generating After Action Reports',
    scope: 'HYBRID',
    statement: 'Generate incident after action reports and persistently incorporate lessons learned.',
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-8'],
    aws: awsHybrids.collectInrAar,
    gcp: gcpHybrids.collectInrAar,
    process_artifacts_required: ['Sample after-action report', 'Lessons-learned tracking record'],
  },
  'KSI-INR-RPI': {
    id: 'KSI-INR-RPI',
    name: 'Reviewing Past Incidents',
    scope: 'HYBRID',
    statement: 'Persistently review past incidents for patterns or vulnerabilities.',
    nist_controls: ['ir-3', 'ir-4', 'ir-4.1', 'ir-5', 'ir-8'],
    aws: awsHybrids.collectInrRpi,
    gcp: gcpHybrids.collectInrRpi,
    process_artifacts_required: ['Past-incident trend/pattern review minutes', 'Incident log retention policy'],
  },
  'KSI-RPL-ARP': {
    id: 'KSI-RPL-ARP',
    name: 'Aligning Recovery Plan',
    scope: 'HYBRID',
    statement: 'Persistently review the alignment of recovery plans with defined recovery objectives.',
    nist_controls: ['cp-2', 'cp-6', 'cp-7', 'cp-10', 'cp-10.2'],
    aws: awsHybrids.collectRplArp,
    gcp: gcpHybrids.collectRplArp,
    process_artifacts_required: ['Recovery plan document', 'Recovery-plan-vs-objectives alignment review minutes'],
  },
  'KSI-RPL-RRO': {
    id: 'KSI-RPL-RRO',
    name: 'Reviewing Recovery Objectives',
    scope: 'HYBRID',
    statement: 'Persistently review desired Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO).',
    nist_controls: ['cp-2.3', 'cp-9', 'cp-10'],
    aws: awsHybrids.collectRplRro,
    gcp: gcpHybrids.collectRplRro,
    process_artifacts_required: ['RTO/RPO register per system', 'Backup-cadence-vs-RPO comparison'],
  },
  'KSI-SCR-MIT': {
    id: 'KSI-SCR-MIT',
    name: 'Mitigating Supply Chain Risk',
    scope: 'HYBRID',
    statement: 'Persistently identify, review, and mitigate potential supply chain risks.',
    nist_controls: ['ac-20', 'sa-9', 'sa-10', 'sa-11', 'sr-5', 'sr-6', 'si-7.1'],
    aws: awsHybrids.collectScrMit,
    gcp: gcpHybrids.collectScrMit,
    process_artifacts_required: ['Supply-chain risk register + mitigations', 'Image scanning/signing policy'],
  },
  'KSI-SVC-PRR': {
    id: 'KSI-SVC-PRR',
    name: 'Preventing Residual Risk',
    scope: 'HYBRID',
    statement: 'Prevent unauthorized and unintended information transfer via shared system resources (residual data in shared/multi-tenant resources).',
    nist_controls: ['sc-4'],
    aws: awsHybrids.collectSvcPrr,
    gcp: gcpHybrids.collectSvcPrr,
    process_artifacts_required: ['Data-isolation/tenancy design doc', 'Public-exposure review record'],
  },

  // ---- AFR technical pointer: Vulnerability Detection & Response ----
  // KSI-AFR-VDR points at the VDR process; the live-scan collector supplies the
  // automated evidence (Inspector v2 / Container Analysis findings, KEV join, SLA
  // breach detection). The detailed VDR-* FRR requirements are additionally tracked
  // via process attestation.
  'KSI-AFR-VDR': {
    id: 'KSI-AFR-VDR',
    name: 'Vulnerability Detection and Response',
    scope: 'HYBRID',
    statement: 'Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.',
    nist_controls: ['ra-5', 'ra-5.2', 'si-2', 'si-3', 'si-5', 'ir-4', 'ca-7'],
    aws: awsVdrScan.collectVdrScan,
    gcp: gcpVdrScan.collectVdrScan,
    process_artifacts_required: [
      'Documented VDR methodology (detection sources + response timeframes)',
      'CISA KEV catalog source/path used for the run (CLOUD_EVIDENCE_KEV_PATH)',
    ],
  },

  // KSI-AFR-PVA and KSI-CSX-SUM are SPECIAL: invoked by the orchestrator after all
  // per-KSI collectors run. They have no provider-specific collector function.
};

/** All KSI IDs currently supported by the script. */
export const SUPPORTED_KSIS = Object.keys(KSI_MAP) as Array<keyof typeof KSI_MAP>;
