"""Map already-collected inventory evidence to PCI DSS v4.0.1 requirement domains.

This is the "MAP" step (research/08 §0.1): pure read from the Stage 1/2 artifact —
NO new AWS calls. For each requirement domain, a builder selects the relevant
already-collected fields from a resource and emits an :class:`EvidenceRow` (only
when the resource is relevant to that domain), traceable to the ARN and carrying
the Stage 2 scope category + confidence.

It also exposes the column→requirement(s) mapping that drives the "PCI Requirement
Mapping" sheet (the whole tool, Stages 1–3).
"""

from __future__ import annotations

from typing import Any, Callable

from pci_inventory.evidence.loader import resource_scope
from pci_inventory.evidence.models import EvidenceRow, RequirementDomain

# --------------------------------------------------------------------------- #
# Column → requirement(s) mapping (drives the PCI Requirement Mapping sheet).
# Spans the whole tool: each inventory data point → the requirement(s) it supports
# + whether it is collected at inventory time (INV) or a Stage 3 follow-up (FOLLOW-UP).
# --------------------------------------------------------------------------- #
COLUMN_REQUIREMENT_MAP: list[tuple[str, str, str]] = [
    # (column / data point, requirement(s), source)
    ("public_exposed / exposure_basis", "1.2, 1.3, 1.4, 11.3", "INV"),
    ("relationships.ingress_rules/egress_rules", "1.2, 1.3", "INV"),
    ("segmentation_role", "1.2.5, 11.4.x", "INV"),
    ("logging_enabled (VPC flow logs)", "1.4, 10.2", "INV"),
    ("public_access_block", "1.3, 1.4, 7.2", "INV"),
    ("imdsv2_required / metadata_hop_limit", "2.2.1, 2.2.6", "INV"),
    ("is_root_account / password_policy_summary", "2.2.2, 8.3, 8.6", "INV"),
    ("encryption_at_rest / _detail", "3.5, 3.6", "INV"),
    ("kms_rotation_enabled / _period_days / key_origin_manager", "3.6.1, 3.7.4", "INV"),
    ("publicly_shared (snapshots/AMIs)", "1.3, 3.x", "INV"),
    ("data_classification", "3.1, 3.2.1", "INV (tag)"),
    ("encryption_in_transit / _detail / tls_min_version", "4.2.1, 2.2.7", "INV"),
    ("cert_expiry_date / cert_key_algo", "4.2.1.1", "INV"),
    ("anti_malware_status", "5.2, 5.3", "INV (NOT_COLLECTABLE — in-guest)"),
    ("guardduty malware findings", "5.x", "FOLLOW-UP"),
    ("is_bespoke_software / software_app / software_version", "6.3.2", "INV"),
    ("eol_status", "6.3.3, 12.3.4", "INV"),
    ("patch_compliance", "6.3.3", "INV"),
    ("vuln_scan_status", "6.3.1, 11.3.1", "INV"),
    ("vuln_findings_summary (Inspector)", "6.3.1, 11.3.1", "INV + FOLLOW-UP"),
    ("WAF web-ACL association", "6.4.2", "FOLLOW-UP"),
    ("iam_policy_data (wildcards, boundaries, trust)", "7.2", "INV"),
    ("Access Analyzer active findings", "7.2.x", "FOLLOW-UP"),
    ("mfa_enabled / mfa_type", "8.4, 8.5", "INV"),
    ("access_key_age_days", "8.3.9, 8.6.3", "INV"),
    ("last_used_age_days", "8.2.6", "INV"),
    ("iam_db_auth", "8.x", "INV"),
    ("cloudtrail trail config (multi-region/validation/KMS/selectors)", "10.2, 10.3", "INV"),
    ("log_retention_days", "10.5.1", "INV + DERIVED"),
    ("change_detection_monitored / Config recorder", "10.7, 11.5", "INV"),
    ("time_sync_source", "10.6", "INV (NOT_COLLECTABLE — in-guest)"),
    ("backup_config (object-lock / versioning / MFA-delete)", "10.5.1, 3.x", "INV"),
    ("Security Hub standard control status", "11.x, 12.x", "FOLLOW-UP"),
    ("Config rule compliance per resource", "2.2, 11.5", "FOLLOW-UP"),
    ("Macie sensitive-data findings", "3.x", "FOLLOW-UP"),
    ("ELBv2 SSL policy ciphers", "4.2.1", "FOLLOW-UP"),
    ("the inventory itself (completeness + currency)", "12.5.1", "INV"),
    ("pci_scope / scope_analysis (Stage 2)", "12.5.2", "INV"),
    ("physical / data-centre controls", "9.x", "SHARED (AWS Artifact AOC)"),
]


def _v(resource: dict[str, Any], *keys: str) -> dict[str, Any]:
    """Pick a subset of fields from a resource record (only present, non-empty)."""
    out: dict[str, Any] = {}
    for k in keys:
        val = resource.get(k)
        if val not in (None, "", [], {}):
            out[k] = val
    return out


def _tri(value: Any) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if value is None:
        return "N/A"
    return str(value)


# --------------------------------------------------------------------------- #
# Per-domain relevance + field selection. Each builder returns the evidence
# ``fields`` dict if the resource is relevant to that domain, else None.
# --------------------------------------------------------------------------- #
_NETWORK_TYPES = {"ec2:security-group", "ec2:network-acl", "ec2:route-table", "ec2:vpc",
                  "ec2:subnet", "ec2:internet-gateway", "ec2:nat-gateway", "ec2:vpc-peering",
                  "ec2:transit-gateway", "ec2:tgw-attachment", "ec2:vpc-endpoint",
                  "networkfirewall:firewall", "fms:policy"}
_INSTANCE_TYPES = {"ec2:instance"}
_DATA_STORE_TYPES = {"s3:bucket", "rds:db-instance", "rds:db-cluster", "dynamodb:table",
                     "redshift:cluster", "redshift-serverless:namespace", "elasticache:cluster",
                     "efs:file-system", "fsx:file-system", "docdb:cluster", "neptune:cluster",
                     "memorydb:cluster", "timestream:database", "qldb:ledger", "opensearch:domain",
                     "backup:vault", "ec2:volume", "ec2:snapshot", "ec2:ami"}
_TLS_ENDPOINT_TYPES = {"elbv2:application", "elbv2:network", "elbv2:load-balancer",
                       "elb:classic-load-balancer", "cloudfront:distribution",
                       "apigateway:rest-api", "apigatewayv2:http-api", "apigatewayv2:websocket-api",
                       "acm:certificate", "iam:server-certificate", "opensearch:domain",
                       "rds:db-instance", "rds:db-cluster", "dms:endpoint"}
_IAM_PRINCIPAL_TYPES = {"iam:user", "iam:role", "iam:group", "iam:policy-customer",
                        "iam:policy-aws", "iam:account-settings", "iam:instance-profile",
                        "sso:permission-set"}
_IDENTITY_TYPES = {"iam:user", "iam:role", "iam:account-settings", "cognito:user-pool"}
_LOGGING_TYPES = {"cloudtrail:trail", "config:recorder", "config:rule", "logs:log-group",
                  "cloudwatch:alarm", "ec2:vpc"}
_SECURITY_SVC_TYPES = {"guardduty:detector", "securityhub:hub", "inspector2:account-status",
                       "macie2:session", "detective:graph", "access-analyzer:analyzer",
                       "config:rule", "config:recorder"}
_BESPOKE_TYPES = {"lambda:function", "ecs:cluster", "eks:cluster", "ecr:repository",
                  "elasticbeanstalk:environment", "states:state-machine", "apigateway:rest-api",
                  "apigatewayv2:http-api"}


def _req1(r):
    if r.get("resource_type") in _NETWORK_TYPES or r.get("public_exposed") is True:
        f = _v(r, "public_exposed", "segmentation_role")
        f["exposure_basis"] = "; ".join(r.get("exposure_basis", []))
        rels = r.get("relationships", {}) or {}
        if rels.get("ingress_rules"):
            f["ingress_rules"] = "; ".join(rels["ingress_rules"][:10])
        if rels.get("egress_rules"):
            f["egress_rules"] = "; ".join(rels["egress_rules"][:10])
        if r.get("resource_type") == "ec2:vpc":
            f["flow_logs"] = _tri(r.get("logging_enabled")) + " — " + (r.get("logging_detail", "") or "")
        f["public_exposed"] = _tri(r.get("public_exposed"))
        return f
    return None


def _req2(r):
    rt = r.get("resource_type")
    if rt in _INSTANCE_TYPES:
        return {"imdsv2_required": _tri(r.get("imdsv2_required")),
                "metadata_hop_limit": r.get("metadata_hop_limit", "N/A"),
                "os_platform_engine": r.get("os_platform_engine", ""),
                "public_exposed": _tri(r.get("public_exposed"))}
    if rt == "iam:account-settings":
        return {"is_root_account": _tri(r.get("is_root_account")),
                "password_policy_summary": r.get("password_policy_summary", "")}
    if rt in _DATA_STORE_TYPES and r.get("public_access_block") is not None:
        return {"public_access_block": _tri(r.get("public_access_block"))}
    return None


def _req3(r):
    if r.get("resource_type") in _DATA_STORE_TYPES:
        f = {"encryption_at_rest": _tri(r.get("encryption_at_rest")),
             "encryption_at_rest_detail": r.get("encryption_at_rest_detail", ""),
             "publicly_shared": _tri(r.get("publicly_shared")),
             "data_classification": r.get("data_classification", "")}
        return f
    if r.get("resource_type") == "kms:key":
        return {"kms_rotation_enabled": _tri(r.get("kms_rotation_enabled")),
                "kms_rotation_period_days": r.get("kms_rotation_period_days", "N/A"),
                "key_origin_manager": r.get("key_origin_manager", "")}
    return None


def _req4(r):
    if r.get("resource_type") in _TLS_ENDPOINT_TYPES:
        f = {"encryption_in_transit": _tri(r.get("encryption_in_transit")),
             "tls_min_version": r.get("tls_min_version", "N/A"),
             "encryption_in_transit_detail": r.get("encryption_in_transit_detail", "")}
        if r.get("cert_expiry_date"):
            f["cert_expiry_date"] = r["cert_expiry_date"]
        if r.get("cert_key_algo") not in (None, "", "N/A"):
            f["cert_key_algo"] = r["cert_key_algo"]
        return f
    return None


def _req5(r):
    if r.get("resource_type") in _INSTANCE_TYPES or r.get("anti_malware_status") not in (None, "N/A"):
        return {"anti_malware_status": r.get("anti_malware_status", "N/A")}
    return None


def _req6(r):
    rt = r.get("resource_type")
    if rt in _INSTANCE_TYPES or rt in _BESPOKE_TYPES or r.get("is_bespoke_software"):
        return {"is_bespoke_software": _tri(r.get("is_bespoke_software")),
                "software_app": r.get("software_app", ""),
                "software_version": r.get("software_version", ""),
                "eol_status": r.get("eol_status", ""),
                "patch_compliance": r.get("patch_compliance", "N/A"),
                "vuln_scan_status": r.get("vuln_scan_status", "N/A"),
                "vuln_findings_summary": r.get("vuln_findings_summary", "N/A")}
    return None


def _req7(r):
    if r.get("resource_type") in _IAM_PRINCIPAL_TYPES:
        ipd = r.get("iam_policy_data", {}) or {}
        f = {"principal_type": ipd.get("principal_type", r.get("resource_type"))}
        if "attached_managed_policies" in ipd:
            f["attached_managed_policies"] = len(ipd["attached_managed_policies"])
        if "inline_policies" in ipd:
            f["inline_policies"] = len(ipd["inline_policies"])
        if ipd.get("permissions_boundary"):
            f["permissions_boundary"] = ipd["permissions_boundary"]
        if ipd.get("trust_principals"):
            f["trust_principals"] = "; ".join(str(p) for p in ipd["trust_principals"][:5])
        return f
    return None


def _req8(r):
    if r.get("resource_type") in _IDENTITY_TYPES:
        return {"mfa_enabled": _tri(r.get("mfa_enabled")),
                "mfa_type": r.get("mfa_type", "N/A"),
                "access_key_age_days": r.get("access_key_age_days", "N/A"),
                "last_used_age_days": r.get("last_used_age_days", "N/A"),
                "is_root_account": _tri(r.get("is_root_account")),
                "password_policy_summary": r.get("password_policy_summary", "")}
    if r.get("iam_db_auth") is not None:
        return {"iam_db_auth": _tri(r.get("iam_db_auth"))}
    return None


def _req10(r):
    rt = r.get("resource_type")
    if rt in _LOGGING_TYPES:
        f = {"logging_enabled": _tri(r.get("logging_enabled")),
             "logging_detail": r.get("logging_detail", "")}
        if rt == "logs:log-group":
            f["log_retention_days"] = r.get("log_retention_days", "N/A")
        if r.get("change_detection_monitored") is not None:
            f["change_detection_monitored"] = _tri(r.get("change_detection_monitored"))
        if r.get("backup_config"):
            f["backup_config"] = r["backup_config"]
        return f
    return None


def _req11(r):
    rt = r.get("resource_type")
    if rt in _SECURITY_SVC_TYPES:
        return {"state_status": r.get("state_status", ""),
                "logging_enabled": _tri(r.get("logging_enabled")),
                "vuln_findings_summary": r.get("vuln_findings_summary", "N/A")}
    if r.get("public_exposed") is True:  # external scan target
        return {"external_scan_target": "Yes",
                "public_ips": "; ".join(r.get("public_ips", [])),
                "dns_names": "; ".join(r.get("dns_names", []))}
    return None


def _req12(r):
    # Every resource contributes to 12.5.1 inventory completeness + 12.5.2 scope.
    return {"resource_type": r.get("resource_type", ""),
            "tag_completeness": r.get("tag_completeness", ""),
            "environment": r.get("environment", ""),
            "owner_team": r.get("owner_team", ""),
            "collection_timestamp": r.get("collection_timestamp", "")}


# requirement -> (sub-reqs, builder)
_BUILDERS: list[tuple[RequirementDomain, str, Callable[[dict], dict | None]]] = [
    (RequirementDomain.REQ1, "1.2, 1.3, 1.4", _req1),
    (RequirementDomain.REQ2, "2.2.1, 2.2.2, 2.2.6, 2.2.7", _req2),
    (RequirementDomain.REQ3, "3.5, 3.6, 3.7", _req3),
    (RequirementDomain.REQ4, "4.2.1, 4.2.1.1", _req4),
    (RequirementDomain.REQ5, "5.2, 5.3", _req5),
    (RequirementDomain.REQ6, "6.3.1, 6.3.2, 6.3.3, 6.4.2", _req6),
    (RequirementDomain.REQ7, "7.2", _req7),
    (RequirementDomain.REQ8, "8.2.6, 8.3, 8.4, 8.5, 8.6", _req8),
    (RequirementDomain.REQ10, "10.2, 10.3, 10.5.1, 10.7", _req10),
    (RequirementDomain.REQ11, "11.3, 11.5", _req11),
    (RequirementDomain.REQ12, "12.5.1, 12.5.2", _req12),
]


def build_evidence_rows(resource: dict[str, Any]) -> list[EvidenceRow]:
    """Build all applicable per-requirement evidence rows for one resource."""
    category, confidence = resource_scope(resource)
    arn = resource.get("arn", "")
    rid = resource.get("resource_id", "")
    rtype = resource.get("resource_type", "")
    name = resource.get("name", "")
    region = resource.get("region", "")
    account = resource.get("account_id", "")
    rows: list[EvidenceRow] = []
    for domain, subreqs, builder in _BUILDERS:
        try:
            fields = builder(resource)
        except Exception:  # noqa: BLE001 - one builder must not break the row set
            fields = None
        if not fields:
            continue
        rows.append(EvidenceRow(
            requirement=domain, sub_requirements=subreqs, resource_arn=arn,
            resource_id=rid, resource_type=rtype, name=name, region=region,
            account_id=account, scope_category=category, scope_confidence=confidence,
            fields=fields))
    return rows
