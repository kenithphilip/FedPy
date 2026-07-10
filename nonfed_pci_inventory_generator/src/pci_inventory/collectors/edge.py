"""Edge / exposure collectors: ELBv2 (ALB/NLB), Classic ELB, API Gateway (REST &
HTTP/WS), CloudFront, Global Accelerator, Route 53, WAFv2, Shield.

This domain carries the highest-value internet-exposure signals for PCI scope:
internet-facing load balancers, public APIs, CDN distributions, and public DNS.
CloudFront, Global Accelerator, Route 53, and WAF (CLOUDFRONT scope) are GLOBAL.
"""

from __future__ import annotations

from typing import Any

from pci_inventory.collectors.base import (
    Collector,
    CollectorContext,
    add_exposure,
    collect_each,
    new_record,
    register,
    set_not_exposed_if_unset,
    synth_arn,
    to_iso,
)
from pci_inventory.schema.models import ResourceRecord
from pci_inventory.utils import GLOBAL_REGION, Sentinel


def tls_min_from_policy(policy_name: str) -> str:
    """Parse an enforced minimum TLS version from an AWS SSL policy name.

    AWS predefined policy names encode the floor, e.g.
    ``ELBSecurityPolicy-TLS13-1-2-2021-06`` -> TLSv1.2,
    ``ELBSecurityPolicy-TLS-1-0-2015-04`` -> TLSv1.0. Returns ``N/A`` if unknown.
    """
    if not policy_name:
        return Sentinel.NA
    p = policy_name.replace("ELBSecurityPolicy-", "")
    for token, ver in (("1-2", "TLSv1.2"), ("1-1", "TLSv1.1"), ("1-0", "TLSv1.0"),
                       ("TLS13", "TLSv1.3"), ("FS-1-2", "TLSv1.2"), ("TLS-1-2", "TLSv1.2")):
        if token in p:
            return ver
    if "1-3" in p:
        return "TLSv1.3"
    return Sentinel.NA


@register
class ELBv2Collector(Collector):
    service = "elbv2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("elbv2")
        lbs = list(ctx.call.paginate(client, "describe_load_balancers", account_id=ctx.account_id,
                                     region=ctx.region, service="elbv2", result_key="LoadBalancers"))
        return [self._build(ctx, client, lb) for lb in lbs if lb]

    def _build(self, ctx: CollectorContext, client: Any, lb: dict[str, Any]) -> ResourceRecord:
        arn = lb["LoadBalancerArn"]
        name = lb.get("LoadBalancerName", "")
        rec = new_record(ctx, service="elbv2", resource_type=f"elbv2:{lb.get('Type','load-balancer')}",
                         resource_id=name, arn=arn, name=name)
        rec.state_status = lb.get("State", {}).get("Code", "")
        rec.creation_date = to_iso(lb.get("CreatedTime"))
        rec.dns_names = [lb["DNSName"]] if lb.get("DNSName") else []
        rec.description_purpose = f"{lb.get('Type','')} load balancer ({lb.get('Scheme','')})"
        rec.add_relationship("vpc", lb.get("VpcId"))
        rec.add_relationship("subnets", [az.get("SubnetId") for az in lb.get("AvailabilityZones", [])])
        rec.add_relationship("security_groups", lb.get("SecurityGroups", []))
        if lb.get("Scheme") == "internet-facing":
            add_exposure(rec, "internet-facing-lb")

        # Listeners → TLS / certs (encryption in transit).
        listeners = ctx.call.call(client.describe_listeners, account_id=ctx.account_id, region=ctx.region,
                                  service="elbv2", operation="DescribeListeners", resource_id=name,
                                  default={"Listeners": []}, LoadBalancerArn=arn)
        tls_policies, certs, tgs = [], [], []
        any_tls = False
        for ls in listeners.get("Listeners", []):
            rec.add_relationship("listeners", ls.get("ListenerArn"))
            if ls.get("Protocol") in ("HTTPS", "TLS"):
                any_tls = True
                if ls.get("SslPolicy"):
                    tls_policies.append(ls["SslPolicy"])
                for c in ls.get("Certificates", []):
                    if c.get("CertificateArn"):
                        certs.append(c["CertificateArn"])
            for act in ls.get("DefaultActions", []):
                if act.get("TargetGroupArn"):
                    tgs.append(act["TargetGroupArn"])
        rec.encryption_in_transit = any_tls if listeners.get("Listeners") else None
        rec.encryption_in_transit_detail = ", ".join(sorted(set(tls_policies)))
        # R2/R3: parsed minimum TLS version across HTTPS/TLS listeners.
        versions = sorted({tls_min_from_policy(p) for p in tls_policies} - {Sentinel.NA})
        if versions:
            rec.tls_min_version = versions[0]  # lowest floor present
            if rec.tls_min_version in ("TLSv1.0", "TLSv1.1"):
                rec.add_note(f"listener allows {rec.tls_min_version} (review 4.2.1)")
        rec.add_relationship("certificates", certs)
        rec.add_relationship("target_groups", tgs)

        # R3: load balancer attributes — access logging, desync, deletion protection.
        attrs = ctx.call.call(client.describe_load_balancer_attributes, account_id=ctx.account_id,
                              region=ctx.region, service="elbv2", operation="DescribeLoadBalancerAttributes",
                              resource_id=name, default={"Attributes": []}, LoadBalancerArn=arn)
        amap = {a.get("Key"): a.get("Value") for a in attrs.get("Attributes", [])}
        access_logs_on = amap.get("access_logs.s3.enabled") == "true"
        rec.logging_enabled = access_logs_on
        rec.logging_detail = (f"access_logs={'on' if access_logs_on else 'off'}"
                              + (f"→{amap.get('access_logs.s3.bucket')}" if access_logs_on else ""))
        rec.deletion_protection = amap.get("deletion_protection.enabled") == "true"
        if amap.get("routing.http.desync_mitigation_mode"):
            rec.add_note(f"desync_mitigation={amap['routing.http.desync_mitigation_mode']}")
        if not access_logs_on:
            rec.add_note("LB access logging disabled (review 10.x)")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["elbv2:DescribeLoadBalancers", "elbv2:DescribeListeners",
                            "elbv2:DescribeLoadBalancerAttributes"]
        return rec


@register
class ClassicELBCollector(Collector):
    service = "elb"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("elb")
        lbs = ctx.call.paginate(client, "describe_load_balancers", account_id=ctx.account_id,
                                region=ctx.region, service="elb", result_key="LoadBalancerDescriptions")
        return collect_each(lbs, lambda lb: self._build(ctx, lb))

    def _build(self, ctx: CollectorContext, lb: dict[str, Any]) -> ResourceRecord:
        name = lb["LoadBalancerName"]
        arn = synth_arn("elasticloadbalancing", ctx.region, ctx.account_id, f"loadbalancer/{name}")
        rec = new_record(ctx, service="elb", resource_type="elb:classic-load-balancer",
                         resource_id=name, arn=arn, name=name)
        rec.creation_date = to_iso(lb.get("CreatedTime"))
        rec.dns_names = [lb["DNSName"]] if lb.get("DNSName") else []
        rec.description_purpose = f"Classic load balancer ({lb.get('Scheme','')})"
        rec.add_relationship("vpc", lb.get("VPCId"))
        rec.add_relationship("subnets", lb.get("Subnets", []))
        rec.add_relationship("security_groups", lb.get("SecurityGroups", []))
        rec.add_relationship("instances", [i.get("InstanceId") for i in lb.get("Instances", [])])
        if lb.get("Scheme") == "internet-facing":
            add_exposure(rec, "internet-facing-lb")
        any_tls = any(li.get("Listener", {}).get("Protocol") in ("HTTPS", "SSL")
                      for li in lb.get("ListenerDescriptions", []))
        rec.encryption_in_transit = any_tls if lb.get("ListenerDescriptions") else None
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["elb:DescribeLoadBalancers"]
        return rec


@register
class ApiGatewayRestCollector(Collector):
    service = "apigateway"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("apigateway")
        apis = ctx.call.paginate(client, "get_rest_apis", account_id=ctx.account_id,
                                 region=ctx.region, service="apigateway", result_key="items")
        return collect_each(apis, lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, api: dict[str, Any]) -> ResourceRecord:
        aid = api["id"]
        arn = synth_arn("apigateway", ctx.region, "", f"/restapis/{aid}")
        rec = new_record(ctx, service="apigateway", resource_type="apigateway:rest-api",
                         resource_id=aid, arn=arn, name=api.get("name", ""))
        rec.tags = dict(api.get("tags", {}))
        rec.creation_date = to_iso(api.get("createdDate"))
        rec.description_purpose = api.get("description", "") or "API Gateway REST API"
        endpoint_types = api.get("endpointConfiguration", {}).get("types", [])
        rec.state_status = ",".join(endpoint_types)
        rec.is_bespoke_software = True
        # PRIVATE endpoints are not internet-exposed; EDGE/REGIONAL are.
        if endpoint_types and "PRIVATE" not in endpoint_types:
            add_exposure(rec, "apigw-public-endpoint")
        elif not endpoint_types:
            add_exposure(rec, "apigw-public-endpoint")
        rec.dns_names = [f"{aid}.execute-api.{ctx.region}.amazonaws.com"]
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["apigateway:GET /restapis"]
        return rec


@register
class ApiGatewayV2Collector(Collector):
    service = "apigatewayv2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("apigatewayv2")
        # get_apis has no boto3 paginator but paginates via NextToken.
        apis = ctx.call.paginate_token(
            client.get_apis, account_id=ctx.account_id, region=ctx.region,
            service="apigatewayv2", operation="GetApis", result_key="Items",
            request_token_param="NextToken", response_token_field="NextToken",
        )
        return collect_each(apis, lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, api: dict[str, Any]) -> ResourceRecord:
        aid = api["ApiId"]
        arn = synth_arn("apigateway", ctx.region, "", f"/apis/{aid}")
        rec = new_record(ctx, service="apigatewayv2", resource_type=f"apigatewayv2:{api.get('ProtocolType','http').lower()}-api",
                         resource_id=aid, arn=arn, name=api.get("Name", ""))
        rec.tags = dict(api.get("Tags", {}))
        rec.creation_date = to_iso(api.get("CreatedDate"))
        rec.description_purpose = api.get("Description", "") or f"API Gateway {api.get('ProtocolType','')} API"
        rec.is_bespoke_software = True
        if api.get("ApiEndpoint"):
            rec.dns_names = [api["ApiEndpoint"]]
            add_exposure(rec, "apigwv2-public-endpoint")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["apigatewayv2:GetApis"]
        return rec


@register
class CloudFrontCollector(Collector):
    service = "cloudfront"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("cloudfront", region="us-east-1")
        dists = ctx.call.paginate(client, "list_distributions", account_id=ctx.account_id,
                                  region=GLOBAL_REGION, service="cloudfront",
                                  result_key=None)
        records: list[ResourceRecord] = []
        for page in dists:
            for d in page.get("DistributionList", {}).get("Items", []) or []:
                records.append(self._build(ctx, d))
        return records

    def _build(self, ctx: CollectorContext, d: dict[str, Any]) -> ResourceRecord:
        did = d["Id"]
        rec = new_record(ctx, service="cloudfront", resource_type="cloudfront:distribution",
                         resource_id=did, arn=d.get("ARN", ""), region=GLOBAL_REGION,
                         name=d.get("DomainName", ""))
        rec.state_status = d.get("Status", "")
        rec.last_modified_activity = to_iso(d.get("LastModifiedTime"))
        rec.dns_names = [d.get("DomainName", "")]
        for alias in d.get("Aliases", {}).get("Items", []) or []:
            rec.dns_names.append(alias)
        rec.description_purpose = d.get("Comment", "") or "CloudFront distribution (CDN)"
        if d.get("Enabled"):
            add_exposure(rec, "cloudfront-distribution")
        vcert = d.get("ViewerCertificate", {})
        # R3: viewer protocol policy (HTTPS enforcement) + min TLS + WAF assoc.
        vpp = d.get("DefaultCacheBehavior", {}).get("ViewerProtocolPolicy", "")
        rec.encryption_in_transit = vpp in ("redirect-to-https", "https-only")
        min_proto = vcert.get("MinimumProtocolVersion", "")
        rec.encryption_in_transit_detail = f"viewer_policy={vpp} min={min_proto}"
        # MinimumProtocolVersion values like TLSv1.2_2021 / TLSv1 / SSLv3.
        rec.tls_min_version = (min_proto.split("_")[0] if min_proto else Sentinel.NA)
        if vpp == "allow-all":
            rec.add_note("viewer protocol allows HTTP (review 4.2.1)")
        if vcert.get("ACMCertificateArn"):
            rec.add_relationship("certificates", vcert["ACMCertificateArn"])
        if d.get("WebACLId"):
            rec.add_relationship("web_acl", d["WebACLId"])
        else:
            rec.add_note("no WAF Web ACL associated (review 6.4.2 for public apps)")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["cloudfront:ListDistributions"]
        return rec


@register
class GlobalAcceleratorCollector(Collector):
    service = "globalaccelerator"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        # Global Accelerator's control plane is in us-west-2.
        client = ctx.client("globalaccelerator", region="us-west-2")
        accels = ctx.call.paginate(client, "list_accelerators", account_id=ctx.account_id,
                                   region=GLOBAL_REGION, service="globalaccelerator",
                                   result_key="Accelerators")
        return collect_each(accels, lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, a: dict[str, Any]) -> ResourceRecord:
        arn = a["AcceleratorArn"]
        rec = new_record(ctx, service="globalaccelerator", resource_type="globalaccelerator:accelerator",
                         resource_id=arn.split("/")[-1], arn=arn, region=GLOBAL_REGION,
                         name=a.get("Name", ""))
        rec.state_status = a.get("Status", "")
        rec.creation_date = to_iso(a.get("CreatedTime"))
        for ipset in a.get("IpSets", []):
            rec.public_ips.extend(ipset.get("IpAddresses", []))
        if a.get("DnsName"):
            rec.dns_names = [a["DnsName"]]
        rec.description_purpose = "Global Accelerator (anycast edge)"
        if a.get("Enabled"):
            add_exposure(rec, "global-accelerator")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["globalaccelerator:ListAccelerators"]
        return rec


@register
class Route53Collector(Collector):
    service = "route53"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("route53", region="us-east-1")
        zones = ctx.call.paginate(client, "list_hosted_zones", account_id=ctx.account_id,
                                  region=GLOBAL_REGION, service="route53", result_key="HostedZones")
        return collect_each(zones, lambda z: self._build(ctx, z))

    def _build(self, ctx: CollectorContext, z: dict[str, Any]) -> ResourceRecord:
        zid = z["Id"].split("/")[-1]
        arn = synth_arn("route53", GLOBAL_REGION, "", f"hostedzone/{zid}")
        rec = new_record(ctx, service="route53", resource_type="route53:hosted-zone",
                         resource_id=zid, arn=arn, region=GLOBAL_REGION, name=z.get("Name", ""))
        is_private = z.get("Config", {}).get("PrivateZone", False)
        rec.state_status = "private" if is_private else "public"
        rec.description_purpose = f"{'Private' if is_private else 'Public'} hosted zone — {z.get('ResourceRecordSetCount',0)} records"
        rec.dns_names = [z.get("Name", "").rstrip(".")]
        if not is_private:
            add_exposure(rec, "public-hosted-zone")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["route53:ListHostedZones"]
        return rec


@register
class WAFv2Collector(Collector):
    """WAFv2 web ACLs. Regional scope per region; CLOUDFRONT scope collected once (global)."""

    service = "wafv2"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        return _collect_wafv2_scope(ctx, "REGIONAL", ctx.region)


@register
class WAFv2GlobalCollector(Collector):
    """CLOUDFRONT-scope WAFv2 ACLs — global, collected once against us-east-1."""

    service = "wafv2"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        return _collect_wafv2_scope(ctx, "CLOUDFRONT", "us-east-1", record_region=GLOBAL_REGION)


def _collect_wafv2_scope(ctx: CollectorContext, scope: str, region: str,
                         record_region: str | None = None) -> list[ResourceRecord]:
    """List + describe WAFv2 web ACLs for one scope (token-paginated)."""
    rrgn = record_region or region
    client = ctx.client("wafv2", region=region)
    # list_web_acls has no boto3 paginator; it paginates via NextMarker.
    acls = ctx.call.paginate_token(
        client.list_web_acls, account_id=ctx.account_id, region=rrgn,
        service="wafv2", operation="ListWebACLs", result_key="WebACLs",
        request_token_param="NextMarker", response_token_field="NextMarker",
        Scope=scope,
    )
    out = []
    for acl in acls:
        rec = new_record(ctx, service="wafv2", resource_type=f"wafv2:web-acl-{scope.lower()}",
                         resource_id=acl.get("Id", ""), arn=acl.get("ARN", ""),
                         region=rrgn, name=acl.get("Name", ""))
        rec.description_purpose = acl.get("Description", "") or f"WAFv2 Web ACL ({scope})"
        rec.source_calls = ["wafv2:ListWebACLs"]
        # R3: GetWebACL for default action + rule count; logging config; associations.
        detail = ctx.call.call(client.get_web_acl, account_id=ctx.account_id, region=rrgn,
                               service="wafv2", operation="GetWebACL", resource_id=acl.get("Id", ""),
                               default=None, Name=acl.get("Name", ""), Scope=scope, Id=acl.get("Id", ""))
        if detail and detail.get("WebACL"):
            w = detail["WebACL"]
            default_action = "Allow" if "Allow" in w.get("DefaultAction", {}) else "Block"
            rec.state_status = f"default_action={default_action} rules={len(w.get('Rules', []))}"
            if default_action == "Allow":
                rec.add_note("Web ACL default action is Allow (review 6.4.2 blocking posture)")
            rec.source_calls.append("wafv2:GetWebACL")
        # Logging configuration (Req 10 / 6.4.2).
        if acl.get("ARN"):
            log_cfg = ctx.call.call(client.get_logging_configuration, account_id=ctx.account_id, region=rrgn,
                                    service="wafv2", operation="GetLoggingConfiguration",
                                    resource_id=acl.get("Id", ""), default=None, ResourceArn=acl["ARN"])
            rec.logging_enabled = bool(log_cfg and log_cfg.get("LoggingConfiguration"))
            if not rec.logging_enabled:
                rec.add_note("WAF logging not configured (review 10.x)")
            rec.source_calls.append("wafv2:GetLoggingConfiguration")
        rec.public_exposed = False
        out.append(rec)
    return out


@register
class ShieldCollector(Collector):
    service = "shield"
    is_global = True

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        client = ctx.client("shield", region="us-east-1")
        sub = ctx.call.call(client.describe_subscription, account_id=ctx.account_id, region=GLOBAL_REGION,
                            service="shield", operation="DescribeSubscription", default=None)
        out: list[ResourceRecord] = []
        if sub and sub.get("Subscription"):
            s = sub["Subscription"]
            rec = new_record(ctx, service="shield", resource_type="shield:subscription",
                             resource_id="shield-advanced", arn=synth_arn("shield", GLOBAL_REGION, ctx.account_id, "subscription"),
                             region=GLOBAL_REGION, name="Shield Advanced")
            rec.state_status = "active"
            rec.creation_date = to_iso(s.get("StartTime"))
            rec.description_purpose = "Shield Advanced subscription (DDoS protection)"
            rec.public_exposed = False
            rec.source_calls = ["shield:DescribeSubscription"]
            out.append(rec)
        protections = ctx.call.call(client.list_protections, account_id=ctx.account_id, region=GLOBAL_REGION,
                                    service="shield", operation="ListProtections", default={"Protections": []})
        for p in (protections or {}).get("Protections", []):
            rec = new_record(ctx, service="shield", resource_type="shield:protection",
                             resource_id=p.get("Id", ""), arn=p.get("ProtectionArn", ""),
                             region=GLOBAL_REGION, name=p.get("Name", ""))
            rec.description_purpose = "Shield protection"
            rec.add_relationship("protected_resource", p.get("ResourceArn"))
            rec.public_exposed = False
            rec.source_calls = ["shield:ListProtections"]
            out.append(rec)
        return out
