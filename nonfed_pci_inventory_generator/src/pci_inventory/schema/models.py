"""The canonical inventory record model — the 43-column data contract.

This module is the single source of truth for the inventory schema defined in
``research/02-column-schema.md``. Collectors build :class:`ResourceRecord`
instances; writers serialize them. The :data:`COLUMNS` list drives the workbook
columns, the CSV header, and the Data Dictionary sheet, so the contract cannot
drift between code and documentation.

Stages 2 and 3 may ADD fields (``pci_scope`` gets populated, evidence blocks get
attached) but must not remove or rename the Stage 1 fields.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any

from pci_inventory.utils import Sentinel, iso_now


# --------------------------------------------------------------------------- #
# Column metadata — drives the Data Dictionary sheet and ordering everywhere.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ColumnSpec:
    """Metadata for a single inventory column (for the Data Dictionary sheet)."""

    key: str  # dataclass field / json key
    title: str  # human header in the workbook/CSV
    definition: str
    dtype: str  # logical type: str|bool|tri-bool|datetime|list|dict|enum
    example: str
    source: str  # source API / derivation
    mandatory: bool  # mandatory (vs best-effort) per the schema research
    pci_refs: str  # supporting PCI DSS requirement(s)
    risk_flag: bool = False  # subject to conditional risk highlighting


# Order here == column order in the master sheet, CSV, and Data Dictionary.
COLUMNS: list[ColumnSpec] = [
    ColumnSpec("arn", "ARN", "Canonical AWS ARN (primary unique key); synthesized if the service has no native ARN.", "str", "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc", "per-service", True, "12.5.1"),
    ColumnSpec("resource_id", "Resource ID", "Native short resource id.", "str", "i-0abc123", "per-service", True, "12.5.1"),
    ColumnSpec("account_id", "Account ID", "12-digit AWS account id.", "str", "111122223333", "sts:GetCallerIdentity", True, "12.5.1, A1"),
    ColumnSpec("account_alias", "Account Alias", "IAM account alias or configured friendly name.", "str", "acme-prod", "iam:ListAccountAliases", False, "12.5.1"),
    ColumnSpec("region", "Region", "AWS region; GLOBAL for global services.", "str", "us-east-1", "session/config", True, "12.5.1"),
    ColumnSpec("availability_zone", "Availability Zone", "AZ if the resource is zonal.", "str", "us-east-1a", "per-service", False, "12.5.1"),
    ColumnSpec("service", "Service", "AWS service namespace.", "str", "ec2", "collector", True, "12.5.1"),
    ColumnSpec("resource_type", "Resource Type", "Specific type within the service.", "str", "ec2:instance", "collector", True, "12.5.1, 2.2.1"),
    ColumnSpec("name", "Name", "Name tag or service name field.", "str", "web-01", "tags Name / per-service", True, "12.5.1"),
    ColumnSpec("description_purpose", "Description / Purpose", "Function/use/role — the 12.5.1 description.", "str", "Internet-facing app LB", "tags / per-service / derived", True, "12.5.1", risk_flag=False),
    ColumnSpec("environment", "Environment", "Environment from tags (environment/env/stage).", "str", "prod", "tags", False, "12.5.2"),
    ColumnSpec("owner_team", "Owner / Team", "Owner/team from tags (owner/team/cost-center).", "str", "payments", "tags", False, "12.5.1"),
    ColumnSpec("pci_scope", "PCI Scope", "Scope classification. Stage 1 placeholder; populated in Stage 2.", "enum", Sentinel.PENDING_STAGE2, "Stage 2", True, "12.5.1, 12.5.2"),
    ColumnSpec("pci_scope_basis", "PCI Scope Basis", "Reason/evidence for the scope classification. Empty until Stage 2.", "str", "", "Stage 2", True, "12.5.2"),
    ColumnSpec("data_classification", "Data Classification", "Data sensitivity if inferable from tag/service semantics; else NOT_COLLECTED.", "str", "chd / NOT_COLLECTED", "tags data-classification", False, "3.1, 3.2.1"),
    ColumnSpec("os_platform_engine", "OS / Platform / Engine", "OS, platform, or DB engine.", "str", "Amazon Linux 2 / postgres", "per-service", False, "2.2.1, 12.3.4"),
    ColumnSpec("os_platform_version", "OS / Platform Version", "Version of the OS/platform/engine.", "str", "14.7", "per-service", False, "6.3.2, 12.3.4"),
    ColumnSpec("instance_type", "Instance / Compute Type", "Hardware/compute size class for compute resources (EC2 instance type, RDS DB instance class).", "str", "m5.2xlarge / db.r6g.xlarge", "per-service", False, "2.2.1, 12.5.1"),
    ColumnSpec("imdsv2_required", "IMDSv2 Required", "EC2 instance metadata service requires session tokens (IMDSv2 enforced).", "tri-bool", "Yes", "ec2:DescribeInstances MetadataOptions.HttpTokens", False, "2.2.1, 2.2.6", risk_flag=True),
    ColumnSpec("metadata_hop_limit", "IMDS Hop Limit", "IMDS PUT response hop limit (1 = not proxy/container-reachable).", "str", "1", "ec2 MetadataOptions.HttpPutResponseHopLimit", False, "2.2.1"),
    ColumnSpec("software_app", "Software / App", "Bespoke/app identifier (function name, image, platform).", "str", "orders-api", "per-service / tags", False, "6.3.2"),
    ColumnSpec("software_version", "Software Version", "App / image / package version.", "str", "1.4.2", "per-service", False, "6.3.2, 12.3.4"),
    ColumnSpec("is_bespoke_software", "Bespoke Software", "Whether the component runs custom/bespoke code (heuristic).", "tri-bool", "Yes", "derived", False, "6.3.2"),
    ColumnSpec("eol_status", "EOL Status", "Vendor end-of-life / unsupported signal for OS/engine/runtime.", "str", "EOL / supported / unknown", "derived from version", False, "12.3.4, 6.3.3"),
    ColumnSpec("patch_compliance", "Patch Compliance", "SSM patch-baseline compliance (best-effort; SSM-managed hosts only).", "str", "COMPLIANT / NON_COMPLIANT / NOT_COLLECTABLE", "ssm:DescribeInstancePatchStates", False, "6.3.3, 6.4", risk_flag=True),
    ColumnSpec("vuln_scan_status", "Vuln Scan Status", "Inspector scan coverage state for the component.", "str", "enabled / not-covered / NOT_COLLECTABLE", "inspector2:ListCoverage", False, "11.3.1, 6.3.3"),
    ColumnSpec("vuln_findings_summary", "Vuln Findings", "Open vulnerability findings by severity (no detail/CHD).", "str", "crit:0 high:2", "inspector2:ListFindings", False, "11.3.1, 6.3.1", risk_flag=True),
    ColumnSpec("anti_malware_status", "Anti-Malware", "Anti-malware coverage. In-guest; usually NOT_COLLECTABLE read-only.", "str", "NOT_COLLECTABLE / guardduty-malware-protection", "GuardDuty / n/a", False, "5.2, 5.3"),
    ColumnSpec("public_exposed", "Public Exposed", "Internet-reachable (public IP, internet-facing LB, public S3/API/CF, SG open to 0.0.0.0/0).", "tri-bool", "Yes", "derived", True, "1.2, 1.3, 1.4", risk_flag=True),
    ColumnSpec("exposure_basis", "Exposure Basis", "Concrete reason(s) for public_exposed.", "list", "public-ip; sg 0.0.0.0/0:443", "derived", True, "1.3.x"),
    ColumnSpec("publicly_shared", "Publicly Shared", "Shared beyond the account (public snapshot/AMI, RAM share, public RDS).", "tri-bool", "No", "DescribeSnapshotAttribute / DescribeImageAttribute / RDS", False, "1.3, 3.x, 7.2", risk_flag=True),
    ColumnSpec("public_access_block", "Public Access Block", "S3 account+bucket Block Public Access fully on (all 4 flags).", "tri-bool", "Yes", "s3:GetPublicAccessBlock", False, "1.3, 1.4, 7.2", risk_flag=True),
    ColumnSpec("segmentation_role", "Segmentation Role", "Whether the component is a network segmentation/NSC control.", "str", "nsc / none", "derived from resource_type", False, "1.2, 11.4.5"),
    ColumnSpec("private_ips", "Private IPs", "Private IPv4/IPv6 addresses.", "list", "10.0.1.4", "per-service / ENI", False, "1.2"),
    ColumnSpec("public_ips", "Public IPs", "Public IPs / EIPs.", "list", "52.1.2.3", "per-service / ENI", False, "1.3", risk_flag=True),
    ColumnSpec("dns_names", "DNS Names", "Public/private DNS names, endpoints, FQDNs.", "list", "api.acme.com", "per-service", False, "1.2"),
    ColumnSpec("encryption_at_rest", "Encryption at Rest", "Encrypted at rest (Yes/No/N/A).", "tri-bool", "Yes", "per-service", True, "3.5, 3.6", risk_flag=True),
    ColumnSpec("encryption_at_rest_detail", "Encryption at Rest Detail", "KMS key ARN / SSE algorithm / mode.", "str", "aws:kms arn:…key/…", "per-service", False, "3.6, 3.7"),
    ColumnSpec("kms_rotation_enabled", "KMS Rotation Enabled", "Automatic key rotation enabled (customer-managed KMS keys).", "tri-bool", "Yes", "kms:GetKeyRotationStatus", False, "3.6.1, 3.7.4", risk_flag=True),
    ColumnSpec("kms_rotation_period_days", "KMS Rotation Period", "Configured KMS rotation period in days.", "str", "365", "kms:GetKeyRotationStatus RotationPeriodInDays", False, "3.6.1.2"),
    ColumnSpec("key_origin_manager", "Key Origin / Manager", "KMS key material origin and manager (customer/aws/external/cloudhsm).", "str", "customer-managed", "kms:DescribeKey KeyManager,Origin", False, "3.6, 3.7"),
    ColumnSpec("encryption_in_transit", "Encryption in Transit", "TLS/in-transit enforced (Yes/No/N/A).", "tri-bool", "Yes", "per-service", False, "4.2.1, 2.2.7", risk_flag=True),
    ColumnSpec("encryption_in_transit_detail", "Encryption in Transit Detail", "TLS policy / min version / cert ref.", "str", "ELBSecurityPolicy-TLS13-1-2", "per-service", False, "4.2.1"),
    ColumnSpec("tls_min_version", "TLS Min Version", "Enforced minimum TLS version (parsed, not the raw policy name).", "str", "TLSv1.2", "derived from listener/CF/API GW/RDS", False, "4.2.1, 2.2.7", risk_flag=True),
    ColumnSpec("cert_expiry_date", "Cert Expiry", "Certificate not-after date (UTC).", "datetime", "2026-09-01T00:00:00Z", "acm:DescribeCertificate NotAfter", False, "4.2.1.1", risk_flag=True),
    ColumnSpec("cert_key_algo", "Cert Key Algorithm", "Certificate public-key algorithm and size.", "str", "RSA-2048", "acm:DescribeCertificate KeyAlgorithm", False, "4.2.1, 3.6"),
    ColumnSpec("logging_enabled", "Logging Enabled", "Resource-level logging on (Yes/No/N/A).", "tri-bool", "Yes", "per-service", True, "10.2, 10.3", risk_flag=True),
    ColumnSpec("logging_detail", "Logging Detail", "What logging is on and its destination.", "str", "flowlogs→cwl /vpc/flow", "per-service", False, "10.2"),
    ColumnSpec("log_retention_days", "Log Retention (days)", "Retention period of the log destination (numeric for the 10.5.1 12-month test).", "str", "400", "logs:DescribeLogGroups retentionInDays", False, "10.5.1", risk_flag=True),
    ColumnSpec("change_detection_monitored", "Change Detection", "Covered by AWS Config recorder (change tracking) / FIM.", "tri-bool", "Yes", "derived from config recorder coverage", False, "11.5.2, 10.7"),
    ColumnSpec("time_sync_source", "Time Sync Source", "NTP/time-sync source. In-guest; typically NOT_COLLECTABLE.", "str", "NOT_COLLECTABLE", "n/a (in-guest)", False, "10.6"),
    ColumnSpec("backup_config", "Backup Config", "Backup enabled / retention / versioning / PITR.", "str", "7 days / versioning=Enabled", "per-service", False, "10.5.1, 12.10"),
    ColumnSpec("deletion_protection", "Deletion Protection", "Deletion/termination protection enabled (RDS/ELB/EC2).", "tri-bool", "Yes", "per-service", False, "10.5.1"),
    ColumnSpec("auto_minor_version_upgrade", "Auto Minor Upgrade", "Auto minor-version upgrade enabled (RDS/ElastiCache).", "tri-bool", "Yes", "rds AutoMinorVersionUpgrade", False, "6.3.3"),
    # --- identity / auth (mostly IAM & identity-store records) ---
    ColumnSpec("mfa_enabled", "MFA Enabled", "MFA configured for the principal / root / user-pool.", "tri-bool", "Yes", "credential report / iam:ListMFADevices / cognito", False, "8.4, 8.5", risk_flag=True),
    ColumnSpec("mfa_type", "MFA Type", "Hardware vs virtual MFA.", "str", "virtual / hardware", "iam:ListVirtualMFADevices", False, "8.4.2"),
    ColumnSpec("access_key_age_days", "Access Key Age (days)", "Age of the oldest active access key for the principal.", "str", "412", "credential report access_key_*_last_rotated", False, "8.3.9, 8.6.3", risk_flag=True),
    ColumnSpec("last_used_age_days", "Last Used Age (days)", "Days since principal/key/role last used (dormancy).", "str", "220", "GetAccessKeyLastUsed / RoleLastUsed / report", False, "8.2.6", risk_flag=True),
    ColumnSpec("is_root_account", "Root Account", "Flags the account root principal / root usage indicators.", "tri-bool", "No", "credential report <root_account>", False, "8.2.2, 2.2.2", risk_flag=True),
    ColumnSpec("password_policy_summary", "Password Policy", "Account password policy key parameters.", "str", "len14 reuse4 maxage90", "iam:GetAccountPasswordPolicy", False, "8.3.6, 8.3.7, 8.3.9"),
    ColumnSpec("iam_db_auth", "IAM DB Auth", "IAM database authentication enabled (RDS/Aurora).", "tri-bool", "Yes", "rds IAMDatabaseAuthenticationEnabled", False, "8.x"),
    ColumnSpec("creation_date", "Creation Date", "Resource creation time (UTC).", "datetime", "2025-01-04T12:00:00Z", "per-service", False, "12.5.1"),
    ColumnSpec("last_modified_activity", "Last Modified / Activity", "Last modification/config-change/activity time (UTC).", "datetime", "2026-06-01T09:30:00Z", "per-service", False, "12.5.1, 8.2.6"),
    ColumnSpec("state_status", "State / Status", "Lifecycle state.", "str", "running / available", "per-service", True, "12.5.1"),
    ColumnSpec("tags", "Tags", "All tags as key=value pairs.", "dict", "Name=web-01; env=prod", "per-service tags", True, "12.5.2"),
    ColumnSpec("tag_completeness", "Tag Completeness", "Required governance tags present (configurable set).", "str", "3/4 (missing: owner)", "derived", False, "12.5.2"),
    ColumnSpec("relationships", "Relationships", "Typed references to related resources (adjacency).", "dict", "security_groups=[sg-…]", "per-service", True, "12.5.2, 1.2"),
    ColumnSpec("iam_policy_data", "IAM / Policy Data", "Raw IAM/identity & resource-policy data for the Stage 2 IAM graph.", "dict", "{...}", "IAM/STS/resource policy", True, "7.x, 8.x"),
    ColumnSpec("notes", "Notes", "Free-text collector notes / caveats / partial-collection reasons.", "str", "flow logs: ACCESS_DENIED", "collector", False, "12.5.1"),
    ColumnSpec("collection_timestamp", "Collection Timestamp", "UTC time this record was collected.", "datetime", "2026-06-29T00:00:00Z", "runtime", True, "12.5.1"),
    ColumnSpec("collector_version", "Collector Version", "Tool version that produced the record.", "str", "0.1.0", "runtime", True, "traceability"),
    ColumnSpec("source_calls", "Source API Calls", "API calls used to build the record (audit trail).", "list", "ec2:DescribeInstances", "collector", False, "traceability"),
]

COLUMN_KEYS: list[str] = [c.key for c in COLUMNS]


# Logical domain tabs in the workbook. A resource's service maps to one domain.
DOMAINS: dict[str, set[str]] = {
    "Compute": {"ec2", "autoscaling", "lambda", "ecs", "eks", "ecr", "batch", "lightsail", "elasticbeanstalk"},
    "Network": {"vpc", "directconnect"},
    "Storage": {"s3", "efs", "fsx", "storagegateway", "backup"},
    "Database": {"rds", "dynamodb", "elasticache", "redshift", "redshift-serverless", "docdb",
                 "neptune", "memorydb", "timestream", "qldb", "opensearch", "dms"},
    "IAM": {"iam", "sso", "identitystore", "cognito-idp", "cognito-identity", "access-analyzer"},
    "Security": {"kms", "cloudhsm", "acm", "acm-pca", "secretsmanager", "ssm", "guardduty", "securityhub", "inspector2", "macie2", "detective", "auditmanager"},
    "Logging": {"cloudtrail", "logs", "cloudwatch", "config", "events"},
    "Edge/Exposure": {"elbv2", "elb", "apigateway", "apigatewayv2", "cloudfront", "globalaccelerator",
                      "route53", "wafv2", "waf", "shield", "network-firewall", "fms"},
    "Management": {"organizations", "controltower", "account", "support", "health", "ram"},
    "Messaging": {"sns", "sqs", "kinesis", "states", "mq"},
}


def domain_for_service(service: str) -> str:
    """Return the workbook domain tab for a service namespace ('Other' if none)."""
    for domain, services in DOMAINS.items():
        if service in services:
            return domain
    return "Other"


# --------------------------------------------------------------------------- #
# The record.
# --------------------------------------------------------------------------- #
@dataclass
class ResourceRecord:
    """A single normalized inventory record conforming to the column contract.

    Mandatory identity fields are required at construction; everything else has a
    schema-appropriate default so a collector can populate only what it knows and
    leave the rest as a meaningful blank/sentinel.
    """

    # --- identity (mandatory) ---
    arn: str
    resource_id: str
    account_id: str
    region: str
    service: str
    resource_type: str

    # --- descriptive ---
    account_alias: str = ""
    availability_zone: str = Sentinel.NA
    name: str = ""
    description_purpose: str = ""
    environment: str = ""
    owner_team: str = ""

    # --- scope (deferred to Stage 2) ---
    pci_scope: str = Sentinel.PENDING_STAGE2
    pci_scope_basis: str = ""
    data_classification: str = Sentinel.NOT_COLLECTED

    # --- platform / software ---
    os_platform_engine: str = Sentinel.NA
    os_platform_version: str = Sentinel.NA
    instance_type: str = Sentinel.NA
    imdsv2_required: bool | None = None
    metadata_hop_limit: str = Sentinel.NA
    software_app: str = Sentinel.NA
    software_version: str = Sentinel.NA
    is_bespoke_software: bool | None = None
    eol_status: str = ""
    # Host-centric controls: default N/A; compute collectors set the real value
    # (or NOT_COLLECTABLE for in-guest facts).
    patch_compliance: str = Sentinel.NA
    vuln_scan_status: str = Sentinel.NA
    vuln_findings_summary: str = Sentinel.NA
    anti_malware_status: str = Sentinel.NA

    # --- exposure / network ---
    public_exposed: bool | None = None
    exposure_basis: list[str] = field(default_factory=list)
    publicly_shared: bool | None = None
    public_access_block: bool | None = None
    segmentation_role: str = "none"
    private_ips: list[str] = field(default_factory=list)
    public_ips: list[str] = field(default_factory=list)
    dns_names: list[str] = field(default_factory=list)

    # --- crypto / logging / backup ---
    encryption_at_rest: bool | None = None
    encryption_at_rest_detail: str = ""
    kms_rotation_enabled: bool | None = None
    kms_rotation_period_days: str = Sentinel.NA
    key_origin_manager: str = Sentinel.NA
    encryption_in_transit: bool | None = None
    encryption_in_transit_detail: str = ""
    tls_min_version: str = Sentinel.NA
    cert_expiry_date: str = ""
    cert_key_algo: str = Sentinel.NA
    logging_enabled: bool | None = None
    logging_detail: str = ""
    log_retention_days: str = Sentinel.NA
    change_detection_monitored: bool | None = None
    time_sync_source: str = Sentinel.NA  # set NOT_COLLECTABLE on hosts (in-guest)
    backup_config: str = ""

    # --- lifecycle ---
    deletion_protection: bool | None = None
    auto_minor_version_upgrade: bool | None = None
    # --- identity / auth ---
    mfa_enabled: bool | None = None
    mfa_type: str = Sentinel.NA
    access_key_age_days: str = Sentinel.NA
    last_used_age_days: str = Sentinel.NA
    is_root_account: bool | None = None
    password_policy_summary: str = Sentinel.NA
    iam_db_auth: bool | None = None
    creation_date: str = ""
    last_modified_activity: str = ""
    state_status: str = ""

    # --- governance ---
    tags: dict[str, str] = field(default_factory=dict)
    tag_completeness: str = ""

    # --- handoff data for Stages 2/3 ---
    relationships: dict[str, list[str]] = field(default_factory=dict)
    iam_policy_data: dict[str, Any] = field(default_factory=dict)

    # --- provenance ---
    notes: str = ""
    collection_timestamp: str = field(default_factory=iso_now)
    collector_version: str = ""
    source_calls: list[str] = field(default_factory=list)

    # ----------------------------------------------------------------------- #
    def add_note(self, note: str) -> None:
        """Append a note, preserving any earlier notes (semicolon-separated)."""
        if not note:
            return
        self.notes = f"{self.notes}; {note}".lstrip("; ") if self.notes else note

    def add_relationship(self, key: str, values: Any) -> None:
        """Merge values into a typed relationship list (dedup, order-stable)."""
        from pci_inventory.utils import listify

        existing = self.relationships.setdefault(key, [])
        for v in listify(values):
            if v not in existing:
                existing.append(v)

    def to_dict(self) -> dict[str, Any]:
        """Return the record as an ordered dict keyed by the column contract."""
        raw = dataclasses.asdict(self)
        return {key: raw[key] for key in COLUMN_KEYS}

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Deterministic sort key: (account, region, service, resource id)."""
        return (self.account_id, self.region, self.service, self.resource_id)
