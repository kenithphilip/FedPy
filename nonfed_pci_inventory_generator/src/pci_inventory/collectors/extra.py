"""Additional service collectors added in the re-audit (R4).

Grouped here to keep the original domain modules stable:
- Network: AWS Network Firewall, Firewall Manager, RAM resource shares.
- Patch/Vuln: SSM patch compliance + managed-instance info, ECR scan findings.
- Data stores: OpenSearch, Redshift Serverless, RDS Proxy, DMS.
- Identity: IAM Identity Center (SSO) + Identity Store.

All read-only. Each is best-effort: a service not enabled / not authorized is
captured in the Errors report, never fatal.
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    add_exposure,
    assess_resource_policy_exposure,
    collect_each,
    new_record,
    register,
    set_not_exposed_if_unset,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION, Sentinel, tags_to_dict


# --------------------------------------------------------------------------- #
# Network perimeter / segmentation
# --------------------------------------------------------------------------- #
@register
class NetworkFirewallCollector(Collector):
    service = "network-firewall"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("network-firewall")
        firewalls = ctx.call.paginate(client, "list_firewalls", account_id=ctx.account_id,
                                      region=ctx.region, service="network-firewall",
                                      result_key="Firewalls")
        out = []
        for fw in firewalls:
            name = fw.get("FirewallName", "")
            arn = fw.get("FirewallArn", "")
            desc = ctx.call.call(client.describe_firewall, account_id=ctx.account_id, region=ctx.region,
                                 service="network-firewall", operation="DescribeFirewall",
                                 resource_id=name, default=None, FirewallArn=arn)
            f = (desc or {}).get("Firewall", fw)
            rec = new_record(ctx, service="network-firewall", resource_type="networkfirewall:firewall",
                             resource_id=name, arn=arn, name=name)
            rec.description_purpose = f.get("Description", "") or "AWS Network Firewall (perimeter NSC)"
            rec.add_relationship("vpc", f.get("VpcId"))
            rec.add_relationship("subnets", [m.get("SubnetId") for m in f.get("SubnetMappings", [])])
            rec.add_relationship("firewall_policy", f.get("FirewallPolicyArn"))
            rec.deletion_protection = bool(f.get("DeleteProtection"))
            # Logging configuration (Req 10).
            logcfg = ctx.call.call(client.describe_logging_configuration, account_id=ctx.account_id,
                                   region=ctx.region, service="network-firewall",
                                   operation="DescribeLoggingConfiguration", resource_id=name,
                                   default=None, FirewallArn=arn)
            dests = (logcfg or {}).get("LoggingConfiguration", {}).get("LogDestinationConfigs", [])
            rec.logging_enabled = bool(dests)
            rec.logging_detail = ", ".join(d.get("LogType", "") for d in dests) if dests else "no logging"
            rec.public_exposed = False
            rec.source_calls = ["network-firewall:ListFirewalls", "network-firewall:DescribeFirewall"]
            out.append(rec)
        return out


@register
class FirewallManagerCollector(Collector):
    """Firewall Manager policies (org-wide). Only meaningful in the FMS admin account."""

    service = "fms"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("fms", region="us-east-1")
        policies = ctx.call.paginate(client, "list_policies", account_id=ctx.account_id,
                                     region=GLOBAL_REGION, service="fms", result_key="PolicyList")
        out = []
        for p in policies:
            rec = new_record(ctx, service="fms", resource_type="fms:policy",
                             resource_id=p.get("PolicyId", ""), arn=p.get("PolicyArn", ""),
                             region=GLOBAL_REGION, name=p.get("PolicyName", ""))
            rec.description_purpose = f"Firewall Manager policy ({p.get('SecurityServiceType','')})"
            rec.state_status = "remediation=" + ("on" if p.get("RemediationEnabled") else "off")
            rec.public_exposed = False
            rec.source_calls = ["fms:ListPolicies"]
            out.append(rec)
        return out


@register
class RAMCollector(Collector):
    """Resource Access Manager shares — cross-account sharing = scope boundary."""

    service = "ram"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ram")
        out: list[ResourceRecord] = []
        for owner in ("SELF", "OTHER-ACCOUNTS"):
            shares = ctx.call.paginate(client, "get_resource_shares", account_id=ctx.account_id,
                                       region=ctx.region, service="ram", result_key="resourceShares",
                                       resourceOwner=owner)
            for s in shares:
                sid = s.get("resourceShareArn", "").split("/")[-1]
                rec = new_record(ctx, service="ram", resource_type="ram:resource-share",
                                 resource_id=sid, arn=s.get("resourceShareArn", ""),
                                 name=s.get("name", ""))
                rec.tags = tags_to_dict(s.get("tags"))
                rec.state_status = f"{s.get('status','')} owner={owner}"
                rec.creation_date = to_iso(s.get("creationTime"))
                allows_external = s.get("allowExternalPrincipals")
                rec.description_purpose = (f"RAM share (owner={owner}, "
                                           f"external_principals={'allowed' if allows_external else 'org-only'})")
                if allows_external:
                    rec.add_note("share allows external (non-org) principals — scope boundary (review 12.5.2)")
                rec.public_exposed = False
                rec.source_calls = ["ram:GetResourceShares"]
                out.append(rec)
        return out


# --------------------------------------------------------------------------- #
# Patch / vulnerability
# --------------------------------------------------------------------------- #
@register
class SSMPatchCollector(Collector):
    """SSM managed-instance patch compliance (best-effort; SSM-managed hosts only)."""

    service = "ssm"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("ssm")
        # Managed instance inventory first (so we know what SSM can see).
        info = ctx.call.paginate(client, "describe_instance_information", account_id=ctx.account_id,
                                 region=ctx.region, service="ssm",
                                 result_key="InstanceInformationList")
        info_list = list(info)
        if not info_list:
            return []
        # Patch states keyed by instance id.
        patch_by_instance: dict[str, dict[str, Any]] = {}
        ids = [i.get("InstanceId") for i in info_list if i.get("InstanceId")]
        for chunk_start in range(0, len(ids), 50):
            chunk = ids[chunk_start:chunk_start + 50]
            states = ctx.call.call(client.describe_instance_patch_states, account_id=ctx.account_id,
                                   region=ctx.region, service="ssm",
                                   operation="DescribeInstancePatchStates", default={"InstancePatchStates": []},
                                   InstanceIds=chunk)
            for st in states.get("InstancePatchStates", []):
                patch_by_instance[st.get("InstanceId")] = st
        out = []
        for i in info_list:
            iid = i.get("InstanceId", "")
            rec = new_record(ctx, service="ssm", resource_type="ssm:managed-instance",
                             resource_id=iid, arn=synth_arn("ssm", ctx.region, ctx.account_id, f"managed-instance/{iid}"),
                             name=i.get("ComputerName", iid))
            rec.os_platform_engine = i.get("PlatformName", i.get("PlatformType", ""))
            rec.os_platform_version = i.get("PlatformVersion", "")
            rec.last_modified_activity = to_iso(i.get("LastPingDateTime"))
            rec.state_status = i.get("PingStatus", "")
            rec.description_purpose = "SSM-managed instance (patch/compliance source)"
            st = patch_by_instance.get(iid)
            if st:
                missing = st.get("MissingCount", 0)
                failed = st.get("FailedCount", 0)
                crit = st.get("CriticalNonCompliantCount", 0)
                compliant = missing == 0 and failed == 0
                rec.patch_compliance = "COMPLIANT" if compliant else "NON_COMPLIANT"
                rec.eol_status = f"missing={missing} failed={failed} critical={crit}"
                if not compliant:
                    rec.add_note(f"patch non-compliant: missing={missing} critical={crit} (review 6.3.3)")
            else:
                rec.patch_compliance = Sentinel.NOT_COLLECTED
            rec.public_exposed = False
            rec.source_calls = ["ssm:DescribeInstanceInformation", "ssm:DescribeInstancePatchStates"]
            out.append(rec)
        return out


# --------------------------------------------------------------------------- #
# Data stores
# --------------------------------------------------------------------------- #
@register
class OpenSearchCollector(Collector):
    service = "opensearch"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("opensearch")
        names = ctx.call.call(client.list_domain_names, account_id=ctx.account_id, region=ctx.region,
                              service="opensearch", operation="ListDomainNames",
                              default={"DomainNames": []})
        out = []
        for dn in names.get("DomainNames", []):
            name = dn.get("DomainName", "")
            desc = ctx.call.call(client.describe_domain, account_id=ctx.account_id, region=ctx.region,
                                 service="opensearch", operation="DescribeDomain", resource_id=name,
                                 default=None, DomainName=name)
            d = (desc or {}).get("DomainStatus", {})
            rec = new_record(ctx, service="opensearch", resource_type="opensearch:domain",
                             resource_id=name, arn=d.get("ARN", ""), name=name)
            rec.os_platform_engine = d.get("EngineVersion", "")
            rec.encryption_at_rest = bool(d.get("EncryptionAtRestOptions", {}).get("Enabled"))
            if d.get("EncryptionAtRestOptions", {}).get("KmsKeyId"):
                rec.add_relationship("kms_key", d["EncryptionAtRestOptions"]["KmsKeyId"])
            n2n = d.get("NodeToNodeEncryptionOptions", {}).get("Enabled")
            ep = d.get("DomainEndpointOptions", {})
            rec.encryption_in_transit = bool(n2n and ep.get("EnforceHTTPS"))
            rec.tls_min_version = ep.get("TLSSecurityPolicy", Sentinel.NA)
            vpc_opts = d.get("VPCOptions", {})
            if vpc_opts.get("VPCId"):
                rec.add_relationship("vpc", vpc_opts.get("VPCId"))
                rec.add_relationship("subnets", vpc_opts.get("SubnetIds", []))
                rec.add_relationship("security_groups", vpc_opts.get("SecurityGroupIds", []))
            else:
                add_exposure(rec, "opensearch-public-endpoint (not VPC-attached)")
            if d.get("Endpoint"):
                rec.dns_names = [d["Endpoint"]]
            assess_resource_policy_exposure(rec, d.get("AccessPolicies"), "opensearch-access-policy")
            rec.description_purpose = "OpenSearch domain (potential data store)"
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["opensearch:ListDomainNames", "opensearch:DescribeDomain"]
            out.append(rec)
        return out


@register
class RedshiftServerlessCollector(Collector):
    service = "redshift-serverless"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("redshift-serverless")
        out: list[ResourceRecord] = []
        namespaces = ctx.call.paginate(client, "list_namespaces", account_id=ctx.account_id,
                                       region=ctx.region, service="redshift-serverless",
                                       result_key="namespaces")
        for ns in namespaces:
            name = ns.get("namespaceName", "")
            rec = new_record(ctx, service="redshift-serverless", resource_type="redshift-serverless:namespace",
                             resource_id=name, arn=ns.get("namespaceArn", ""), name=name)
            rec.encryption_at_rest = bool(ns.get("kmsKeyId"))
            if ns.get("kmsKeyId"):
                rec.add_relationship("kms_key", ns["kmsKeyId"])
            rec.state_status = ns.get("status", "")
            rec.creation_date = to_iso(ns.get("creationDate"))
            rec.description_purpose = "Redshift Serverless namespace (data warehouse)"
            rec.public_exposed = False
            rec.source_calls = ["redshift-serverless:ListNamespaces"]
            out.append(rec)
        workgroups = ctx.call.paginate(client, "list_workgroups", account_id=ctx.account_id,
                                       region=ctx.region, service="redshift-serverless",
                                       result_key="workgroups")
        for wg in workgroups:
            name = wg.get("workgroupName", "")
            rec = new_record(ctx, service="redshift-serverless", resource_type="redshift-serverless:workgroup",
                             resource_id=name, arn=wg.get("workgroupArn", ""), name=name)
            rec.state_status = wg.get("status", "")
            rec.creation_date = to_iso(wg.get("creationDate"))
            rec.description_purpose = "Redshift Serverless workgroup"
            rec.add_relationship("subnets", wg.get("subnetIds", []))
            rec.add_relationship("security_groups", wg.get("securityGroupIds", []))
            rec.add_relationship("namespace", wg.get("namespaceName"))
            if wg.get("publiclyAccessible"):
                add_exposure(rec, "redshift-serverless-publicly-accessible")
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["redshift-serverless:ListWorkgroups"]
            out.append(rec)
        return out


@register
class RDSProxyCollector(Collector):
    service = "rds"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("rds")
        proxies = ctx.call.paginate(client, "describe_db_proxies", account_id=ctx.account_id,
                                    region=ctx.region, service="rds", result_key="DBProxies")
        return collect_each(proxies, lambda p: self._build(ctx, p))

    def _build(self, ctx: CollectorContext, p: dict[str, Any]) -> ResourceRecord:
        name = p.get("DBProxyName", "")
        rec = new_record(ctx, service="rds", resource_type="rds:db-proxy",
                         resource_id=name, arn=p.get("DBProxyArn", ""), name=name)
        rec.state_status = p.get("Status", "")
        rec.creation_date = to_iso(p.get("CreatedDate"))
        rec.description_purpose = "RDS Proxy (DB connection pooling)"
        # RequireTLS = enforced TLS to the proxy (Req 4).
        rec.encryption_in_transit = bool(p.get("RequireTLS"))
        rec.iam_db_auth = any(a.get("IAMAuth") == "REQUIRED" for a in p.get("Auth", []))
        rec.add_relationship("vpc", p.get("VpcId"))
        rec.add_relationship("subnets", p.get("VpcSubnetIds", []))
        rec.add_relationship("security_groups", p.get("VpcSecurityGroupIds", []))
        if p.get("Endpoint"):
            rec.dns_names = [p["Endpoint"]]
        rec.add_relationship("execution_role", p.get("RoleArn"))
        rec.public_exposed = False
        rec.source_calls = ["rds:DescribeDBProxies"]
        return rec


@register
class DMSCollector(Collector):
    service = "dms"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("dms")
        out: list[ResourceRecord] = []
        insts = ctx.call.paginate(client, "describe_replication_instances", account_id=ctx.account_id,
                                  region=ctx.region, service="dms", result_key="ReplicationInstances")
        for r in insts:
            rid = r.get("ReplicationInstanceIdentifier", "")
            rec = new_record(ctx, service="dms", resource_type="dms:replication-instance",
                             resource_id=rid, arn=r.get("ReplicationInstanceArn", ""), name=rid)
            rec.state_status = r.get("ReplicationInstanceStatus", "")
            rec.os_platform_version = r.get("EngineVersion", "")
            rec.encryption_at_rest = bool(r.get("KmsKeyId"))
            if r.get("KmsKeyId"):
                rec.add_relationship("kms_key", r["KmsKeyId"])
            rec.auto_minor_version_upgrade = bool(r.get("AutoMinorVersionUpgrade"))
            if r.get("PubliclyAccessible"):
                add_exposure(rec, "dms-publicly-accessible")
            rec.description_purpose = "DMS replication instance (data in migration)"
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["dms:DescribeReplicationInstances"]
            out.append(rec)
        endpoints = ctx.call.paginate(client, "describe_endpoints", account_id=ctx.account_id,
                                      region=ctx.region, service="dms", result_key="Endpoints")
        for e in endpoints:
            eid = e.get("EndpointIdentifier", "")
            rec = new_record(ctx, service="dms", resource_type="dms:endpoint",
                             resource_id=eid, arn=e.get("EndpointArn", ""), name=eid)
            rec.os_platform_engine = e.get("EngineName", "")
            rec.state_status = e.get("Status", "")
            ssl = e.get("SslMode", "none")
            rec.encryption_in_transit = ssl != "none"
            rec.encryption_in_transit_detail = f"ssl_mode={ssl}"
            if e.get("KmsKeyId"):
                rec.add_relationship("kms_key", e["KmsKeyId"])
            rec.description_purpose = f"DMS {e.get('EndpointType','')} endpoint"
            if ssl == "none":
                rec.add_note("DMS endpoint SSL mode none (review 4.2.1)")
            rec.public_exposed = False
            rec.source_calls = ["dms:DescribeEndpoints"]
            out.append(rec)
        return out


# --------------------------------------------------------------------------- #
# Identity Center (SSO)
# --------------------------------------------------------------------------- #
@register
class IdentityCenterCollector(Collector):
    """IAM Identity Center (SSO) instances + permission sets — primary human access."""

    service = "sso"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        admin = ctx.client("sso-admin")
        instances = ctx.call.call(admin.list_instances, account_id=ctx.account_id, region=ctx.region,
                                  service="sso", operation="ListInstances", default={"Instances": []})
        out: list[ResourceRecord] = []
        for inst in instances.get("Instances", []):
            inst_arn = inst.get("InstanceArn", "")
            store_id = inst.get("IdentityStoreId", "")
            rec = new_record(ctx, service="sso", resource_type="sso:instance",
                             resource_id=store_id or inst_arn.split("/")[-1], arn=inst_arn,
                             name="identity-center")
            rec.description_purpose = "IAM Identity Center instance (SSO)"
            rec.add_relationship("identity_store", store_id)
            rec.public_exposed = False
            rec.source_calls = ["sso-admin:ListInstances"]
            out.append(rec)

            # Permission sets (the access blueprints assigned to accounts).
            ps_arns = ctx.call.paginate(admin, "list_permission_sets", account_id=ctx.account_id,
                                        region=ctx.region, service="sso",
                                        result_key="PermissionSets", InstanceArn=inst_arn)
            for ps_arn in ps_arns:
                ps = ctx.call.call(admin.describe_permission_set, account_id=ctx.account_id, region=ctx.region,
                                   service="sso", operation="DescribePermissionSet", resource_id=ps_arn,
                                   default=None, InstanceArn=inst_arn, PermissionSetArn=ps_arn)
                d = (ps or {}).get("PermissionSet", {})
                rec2 = new_record(ctx, service="sso", resource_type="sso:permission-set",
                                  resource_id=ps_arn.split("/")[-1], arn=ps_arn,
                                  name=d.get("Name", ""))
                rec2.description_purpose = d.get("Description", "") or "Identity Center permission set"
                rec2.state_status = f"session_duration={d.get('SessionDuration','')}"
                rec2.add_relationship("sso_instance", inst_arn)
                rec2.iam_policy_data["principal_type"] = "sso-permission-set"
                rec2.public_exposed = False
                rec2.source_calls = ["sso-admin:ListPermissionSets", "sso-admin:DescribePermissionSet"]
                out.append(rec2)
        return out
