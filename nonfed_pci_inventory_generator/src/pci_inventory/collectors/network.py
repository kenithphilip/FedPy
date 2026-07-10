"""Network collectors: VPCs, subnets, route tables, gateways (IGW/NAT/egress),
peering, transit gateways, ENIs, EIPs, security groups, NACLs, VPC endpoints,
flow logs, Direct Connect, S2S VPN, Client VPN.

These records carry the bulk of the relationship data Stage 2 uses to build its
reachability graph (SG rules, routes, subnet→RT/NACL, VPC→peering/TGW/endpoints),
and the exposure signals (SG open to 0.0.0.0/0, IGW-routed subnets).
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
from pci_inventory.utils import Sentinel, tags_to_dict

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


@register
class VPCCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        vpcs = list(ctx.call.paginate(ec2, "describe_vpcs", account_id=ctx.account_id,
                                      region=ctx.region, service="ec2", result_key="Vpcs"))
        # Pre-fetch related objects once for relationship wiring.
        flow_logs = list(ctx.call.paginate(ec2, "describe_flow_logs", account_id=ctx.account_id,
                                           region=ctx.region, service="ec2", result_key="FlowLogs"))
        # R3: capture flow-log traffic type + delivery status per VPC, not just IDs.
        fl_by_vpc: dict[str, list[dict[str, Any]]] = {}
        for fl in flow_logs:
            if fl.get("ResourceId", "").startswith("vpc-"):
                fl_by_vpc.setdefault(fl["ResourceId"], []).append(fl)
        return collect_each(vpcs, lambda v: self._build(ctx, v, fl_by_vpc))

    def _build(self, ctx: CollectorContext, vpc: dict[str, Any], fl_by_vpc: dict[str, list[dict[str, Any]]]) -> ResourceRecord:
        vid = vpc["VpcId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"vpc/{vid}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:vpc", resource_id=vid, arn=arn)
        rec.tags = tags_to_dict(vpc.get("Tags"))
        rec.state_status = vpc.get("State", "")
        rec.description_purpose = ("Default VPC" if vpc.get("IsDefault") else "VPC") + f" {vpc.get('CidrBlock','')}"
        if vpc.get("IsDefault"):
            rec.add_note("default VPC (review 2.2.x use for in-scope workloads)")
        fls = fl_by_vpc.get(vid, [])
        rec.logging_enabled = bool(fls)
        rec.add_relationship("flow_logs", [fl.get("FlowLogId", "") for fl in fls])
        if fls:
            # Flag if no flow log captures ALL traffic, or any is not delivering.
            traffic_types = {fl.get("TrafficType", "") for fl in fls}
            statuses = {fl.get("DeliverLogsStatus", "") for fl in fls}
            rec.logging_detail = (f"flow logs: traffic={','.join(sorted(traffic_types))} "
                                  f"status={','.join(sorted(statuses))} "
                                  f"dest={','.join(sorted({fl.get('LogDestinationType','') for fl in fls}))}")
            if "ALL" not in traffic_types:
                rec.add_note("flow logs do not capture ALL traffic (review 10.x)")
            if statuses - {"SUCCESS"}:
                rec.add_note("flow log delivery not healthy (review 10.x)")
        else:
            rec.logging_detail = "no flow logs"
            rec.add_note("no VPC flow logs (review 10.x)")
        rec.public_exposed = False
        rec.source_calls = ["ec2:DescribeVpcs", "ec2:DescribeFlowLogs"]
        return rec


@register
class SubnetCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        subnets = list(ctx.call.paginate(ec2, "describe_subnets", account_id=ctx.account_id,
                                         region=ctx.region, service="ec2", result_key="Subnets"))
        rts = list(ctx.call.paginate(ec2, "describe_route_tables", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="RouteTables"))
        nacls = list(ctx.call.paginate(ec2, "describe_network_acls", account_id=ctx.account_id,
                                       region=ctx.region, service="ec2", result_key="NetworkAcls"))
        # Map subnet -> route table and detect IGW-routed (public) subnets.
        rt_by_subnet: dict[str, str] = {}
        igw_subnets: set[str] = set()
        main_rt_public: dict[str, bool] = {}
        for rt in rts:
            has_igw = any(r.get("GatewayId", "").startswith("igw-") for r in rt.get("Routes", []))
            for assoc in rt.get("Associations", []):
                if assoc.get("SubnetId"):
                    rt_by_subnet[assoc["SubnetId"]] = rt["RouteTableId"]
                    if has_igw:
                        igw_subnets.add(assoc["SubnetId"])
                elif assoc.get("Main"):
                    main_rt_public[rt.get("VpcId", "")] = has_igw
        nacl_by_subnet: dict[str, str] = {}
        for nacl in nacls:
            for assoc in nacl.get("Associations", []):
                if assoc.get("SubnetId"):
                    nacl_by_subnet[assoc["SubnetId"]] = nacl["NetworkAclId"]

        def build(sub: dict[str, Any]) -> ResourceRecord:
            sid = sub["SubnetId"]
            arn = sub.get("SubnetArn", "") or synth_arn("ec2", ctx.region, ctx.account_id, f"subnet/{sid}")
            rec = new_record(ctx, service="vpc", resource_type="ec2:subnet", resource_id=sid, arn=arn)
            rec.tags = tags_to_dict(sub.get("Tags"))
            rec.availability_zone = sub.get("AvailabilityZone", Sentinel.NA)
            rec.state_status = sub.get("State", "")
            rec.description_purpose = f"Subnet {sub.get('CidrBlock','')}"
            rec.add_relationship("vpc", sub.get("VpcId"))
            if sid in rt_by_subnet:
                rec.add_relationship("route_table", rt_by_subnet[sid])
                is_public = sid in igw_subnets
            else:
                # Implicit main route table association.
                is_public = main_rt_public.get(sub.get("VpcId", ""), False)
            if sid in nacl_by_subnet:
                rec.add_relationship("nacl", nacl_by_subnet[sid])
            if sub.get("MapPublicIpOnLaunch"):
                rec.notes = "auto-assigns public IPs"
            if is_public:
                add_exposure(rec, "igw-routed-subnet")
            set_not_exposed_if_unset(rec)
            rec.source_calls = ["ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeNetworkAcls"]
            return rec

        return collect_each(subnets, build)


@register
class RouteTableCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        rts = ctx.call.paginate(ec2, "describe_route_tables", account_id=ctx.account_id,
                                region=ctx.region, service="ec2", result_key="RouteTables")
        return collect_each(rts, lambda r: self._build(ctx, r))

    def _build(self, ctx: CollectorContext, rt: dict[str, Any]) -> ResourceRecord:
        rid = rt["RouteTableId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"route-table/{rid}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:route-table", resource_id=rid, arn=arn)
        rec.tags = tags_to_dict(rt.get("Tags"))
        rec.add_relationship("vpc", rt.get("VpcId"))
        subnets = [a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")]
        rec.add_relationship("subnets", subnets)
        # Capture routes as relationship targets for the reachability graph.
        route_targets = []
        for r in rt.get("Routes", []):
            tgt = (r.get("GatewayId") or r.get("NatGatewayId") or r.get("TransitGatewayId")
                   or r.get("VpcPeeringConnectionId") or r.get("NetworkInterfaceId")
                   or r.get("InstanceId") or "")
            dest = r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId") or ""
            if tgt:
                route_targets.append(f"{dest}->{tgt}")
                rec.add_relationship("route_targets", tgt)
        rec.description_purpose = "Route table"
        rec.notes = "; ".join(route_targets[:20])
        if any("igw-" in t for t in route_targets):
            add_exposure(rec, "igw-route")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["ec2:DescribeRouteTables"]
        return rec


@register
class SecurityGroupCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        sgs = ctx.call.paginate(ec2, "describe_security_groups", account_id=ctx.account_id,
                                region=ctx.region, service="ec2", result_key="SecurityGroups")
        return collect_each(sgs, lambda s: self._build(ctx, s))

    def _build(self, ctx: CollectorContext, sg: dict[str, Any]) -> ResourceRecord:
        gid = sg["GroupId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"security-group/{gid}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:security-group",
                         resource_id=gid, arn=arn, name=sg.get("GroupName", ""))
        rec.tags = tags_to_dict(sg.get("Tags"))
        rec.add_relationship("vpc", sg.get("VpcId"))
        rec.description_purpose = sg.get("Description", "") or "Security group"

        def summarize(perms: list[dict[str, Any]], direction: str) -> list[str]:
            rules = []
            for p in perms:
                proto = p.get("IpProtocol", "-1")
                frm, to = p.get("FromPort"), p.get("ToPort")
                port = "all" if proto == "-1" else (f"{frm}" if frm == to else f"{frm}-{to}")
                for rng in p.get("IpRanges", []):
                    cidr = rng.get("CidrIp", "")
                    rules.append(f"{direction} {proto}:{port} {cidr}")
                    if cidr in OPEN_CIDRS and direction == "ingress":
                        add_exposure(rec, f"sg-ingress-open {proto}:{port}")
                for rng in p.get("Ipv6Ranges", []):
                    cidr = rng.get("CidrIpv6", "")
                    rules.append(f"{direction} {proto}:{port} {cidr}")
                    if cidr in OPEN_CIDRS and direction == "ingress":
                        add_exposure(rec, f"sg-ingress-open6 {proto}:{port}")
                for ref in p.get("UserIdGroupPairs", []):
                    if ref.get("GroupId"):
                        rec.add_relationship("referenced_sgs", ref["GroupId"])
                        rules.append(f"{direction} {proto}:{port} sg:{ref['GroupId']}")
            return rules

        ingress = summarize(sg.get("IpPermissions", []), "ingress")
        egress = summarize(sg.get("IpPermissionsEgress", []), "egress")
        rec.relationships["ingress_rules"] = ingress
        rec.relationships["egress_rules"] = egress
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["ec2:DescribeSecurityGroups"]
        return rec


@register
class NetworkAclCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        nacls = ctx.call.paginate(ec2, "describe_network_acls", account_id=ctx.account_id,
                                  region=ctx.region, service="ec2", result_key="NetworkAcls")
        return collect_each(nacls, lambda n: self._build(ctx, n))

    def _build(self, ctx: CollectorContext, nacl: dict[str, Any]) -> ResourceRecord:
        nid = nacl["NetworkAclId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"network-acl/{nid}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:network-acl", resource_id=nid, arn=arn)
        rec.tags = tags_to_dict(nacl.get("Tags"))
        rec.add_relationship("vpc", nacl.get("VpcId"))
        rec.add_relationship("subnets", [a.get("SubnetId") for a in nacl.get("Associations", []) if a.get("SubnetId")])
        rec.description_purpose = ("Default " if nacl.get("IsDefault") else "") + "Network ACL"
        entries = []
        for e in nacl.get("Entries", []):
            entries.append(f"{'in' if not e.get('Egress') else 'out'} #{e.get('RuleNumber')} {e.get('RuleAction')} {e.get('CidrBlock','')}")
        rec.notes = "; ".join(entries[:30])
        rec.public_exposed = False
        rec.source_calls = ["ec2:DescribeNetworkAcls"]
        return rec


@register
class ENICollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        enis = ctx.call.paginate(ec2, "describe_network_interfaces", account_id=ctx.account_id,
                                 region=ctx.region, service="ec2", result_key="NetworkInterfaces")
        return collect_each(enis, lambda e: self._build(ctx, e))

    def _build(self, ctx: CollectorContext, eni: dict[str, Any]) -> ResourceRecord:
        nid = eni["NetworkInterfaceId"]
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"network-interface/{nid}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:network-interface", resource_id=nid, arn=arn)
        rec.tags = tags_to_dict(eni.get("TagSet"))
        rec.availability_zone = eni.get("AvailabilityZone", Sentinel.NA)
        rec.state_status = eni.get("Status", "")
        rec.description_purpose = eni.get("Description", "") or f"ENI ({eni.get('InterfaceType','interface')})"
        rec.add_relationship("vpc", eni.get("VpcId"))
        rec.add_relationship("subnet", eni.get("SubnetId"))
        rec.add_relationship("security_groups", [g.get("GroupId") for g in eni.get("Groups", [])])
        attach = eni.get("Attachment", {})
        if attach.get("InstanceId"):
            rec.add_relationship("attached_to", attach["InstanceId"])
        priv, pub = [], []
        for ip in eni.get("PrivateIpAddresses", []):
            if ip.get("PrivateIpAddress"):
                priv.append(ip["PrivateIpAddress"])
            assoc = ip.get("Association", {})
            if assoc.get("PublicIp"):
                pub.append(assoc["PublicIp"])
        rec.private_ips = sorted(set(priv))
        rec.public_ips = sorted(set(pub))
        if rec.public_ips:
            add_exposure(rec, "eni-public-ip")
        set_not_exposed_if_unset(rec)
        rec.source_calls = ["ec2:DescribeNetworkInterfaces"]
        return rec


@register
class EIPCollector(Collector):
    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        resp = ctx.call.call(ec2.describe_addresses, account_id=ctx.account_id, region=ctx.region,
                             service="ec2", operation="DescribeAddresses", default={"Addresses": []})
        return collect_each(resp.get("Addresses", []), lambda a: self._build(ctx, a))

    def _build(self, ctx: CollectorContext, eip: dict[str, Any]) -> ResourceRecord:
        alloc = eip.get("AllocationId", eip.get("PublicIp", ""))
        arn = synth_arn("ec2", ctx.region, ctx.account_id, f"elastic-ip/{alloc}")
        rec = new_record(ctx, service="vpc", resource_type="ec2:elastic-ip", resource_id=alloc, arn=arn)
        rec.tags = tags_to_dict(eip.get("Tags"))
        rec.public_ips = [eip["PublicIp"]] if eip.get("PublicIp") else []
        if eip.get("PrivateIpAddress"):
            rec.private_ips = [eip["PrivateIpAddress"]]
        rec.description_purpose = "Elastic IP (public address)"
        rec.state_status = "associated" if eip.get("AssociationId") else "unassociated"
        rec.add_relationship("attached_to", eip.get("InstanceId") or eip.get("NetworkInterfaceId"))
        add_exposure(rec, "elastic-ip")
        rec.source_calls = ["ec2:DescribeAddresses"]
        return rec


@register
class GatewayCollector(Collector):
    """Internet, NAT, egress-only gateways, peering, transit gateways, VPC endpoints."""

    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        ec2 = ctx.client("ec2")
        out: list[ResourceRecord] = []

        for igw in ctx.call.paginate(ec2, "describe_internet_gateways", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="InternetGateways"):
            gid = igw["InternetGatewayId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:internet-gateway",
                             resource_id=gid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"internet-gateway/{gid}"))
            rec.tags = tags_to_dict(igw.get("Tags"))
            rec.description_purpose = "Internet gateway"
            rec.add_relationship("vpc", [a.get("VpcId") for a in igw.get("Attachments", []) if a.get("VpcId")])
            add_exposure(rec, "internet-gateway")
            rec.source_calls = ["ec2:DescribeInternetGateways"]
            out.append(rec)

        for nat in ctx.call.paginate(ec2, "describe_nat_gateways", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="NatGateways"):
            nid = nat["NatGatewayId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:nat-gateway",
                             resource_id=nid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"natgateway/{nid}"))
            rec.tags = tags_to_dict(nat.get("Tags"))
            rec.state_status = nat.get("State", "")
            rec.creation_date = to_iso(nat.get("CreateTime"))
            rec.add_relationship("vpc", nat.get("VpcId"))
            rec.add_relationship("subnet", nat.get("SubnetId"))
            for addr in nat.get("NatGatewayAddresses", []):
                if addr.get("PublicIp"):
                    rec.public_ips.append(addr["PublicIp"])
                if addr.get("PrivateIp"):
                    rec.private_ips.append(addr["PrivateIp"])
            rec.description_purpose = f"NAT gateway ({nat.get('ConnectivityType','public')})"
            rec.public_exposed = nat.get("ConnectivityType", "public") == "public"
            rec.source_calls = ["ec2:DescribeNatGateways"]
            out.append(rec)

        for pcx in ctx.call.paginate(ec2, "describe_vpc_peering_connections", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="VpcPeeringConnections"):
            pid = pcx["VpcPeeringConnectionId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:vpc-peering",
                             resource_id=pid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"vpc-peering-connection/{pid}"))
            rec.tags = tags_to_dict(pcx.get("Tags"))
            rec.state_status = pcx.get("Status", {}).get("Code", "")
            rec.description_purpose = "VPC peering connection"
            rec.add_relationship("vpc", [pcx.get("RequesterVpcInfo", {}).get("VpcId"),
                                         pcx.get("AccepterVpcInfo", {}).get("VpcId")])
            rec.public_exposed = False
            rec.source_calls = ["ec2:DescribeVpcPeeringConnections"]
            out.append(rec)

        for tgw in ctx.call.paginate(ec2, "describe_transit_gateways", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="TransitGateways"):
            tid = tgw["TransitGatewayId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:transit-gateway",
                             resource_id=tid, arn=tgw.get("TransitGatewayArn", ""))
            rec.tags = tags_to_dict(tgw.get("Tags"))
            rec.state_status = tgw.get("State", "")
            rec.creation_date = to_iso(tgw.get("CreationTime"))
            rec.description_purpose = tgw.get("Description", "") or "Transit gateway"
            rec.public_exposed = False
            rec.source_calls = ["ec2:DescribeTransitGateways"]
            out.append(rec)

        for tga in ctx.call.paginate(ec2, "describe_transit_gateway_attachments", account_id=ctx.account_id,
                                     region=ctx.region, service="ec2", result_key="TransitGatewayAttachments"):
            aid = tga["TransitGatewayAttachmentId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:tgw-attachment",
                             resource_id=aid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"transit-gateway-attachment/{aid}"))
            rec.tags = tags_to_dict(tga.get("Tags"))
            rec.state_status = tga.get("State", "")
            rec.description_purpose = f"TGW attachment ({tga.get('ResourceType','')})"
            rec.add_relationship("tgw", tga.get("TransitGatewayId"))
            rec.add_relationship("vpc", tga.get("ResourceId") if tga.get("ResourceType") == "vpc" else None)
            rec.public_exposed = False
            rec.source_calls = ["ec2:DescribeTransitGatewayAttachments"]
            out.append(rec)

        for vpce in ctx.call.paginate(ec2, "describe_vpc_endpoints", account_id=ctx.account_id,
                                      region=ctx.region, service="ec2", result_key="VpcEndpoints"):
            eid = vpce["VpcEndpointId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:vpc-endpoint",
                             resource_id=eid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"vpc-endpoint/{eid}"))
            rec.tags = tags_to_dict(vpce.get("Tags"))
            rec.state_status = vpce.get("State", "")
            rec.creation_date = to_iso(vpce.get("CreationTimestamp"))
            rec.description_purpose = f"VPC endpoint for {vpce.get('ServiceName','')} ({vpce.get('VpcEndpointType','')})"
            rec.add_relationship("vpc", vpce.get("VpcId"))
            rec.add_relationship("subnets", vpce.get("SubnetIds", []))
            rec.add_relationship("security_groups", [g.get("GroupId") for g in vpce.get("Groups", [])])
            rec.add_relationship("service_name", vpce.get("ServiceName"))
            if vpce.get("PolicyDocument"):
                rec.iam_policy_data["resource_based_policy"] = vpce["PolicyDocument"]
            rec.public_exposed = False
            rec.source_calls = ["ec2:DescribeVpcEndpoints"]
            out.append(rec)

        return out


@register
class VpnDxCollector(Collector):
    """Site-to-Site VPN, Client VPN, Direct Connect connectivity objects."""

    service = "vpc"

    def collect(self, ctx: CollectorContext) -> list[ResourceRecord]:
        out: list[ResourceRecord] = []
        ec2 = ctx.client("ec2")

        vpn = ctx.call.call(ec2.describe_vpn_connections, account_id=ctx.account_id, region=ctx.region,
                            service="ec2", operation="DescribeVpnConnections", default={"VpnConnections": []})
        for v in vpn.get("VpnConnections", []):
            vid = v["VpnConnectionId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:vpn-connection",
                             resource_id=vid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"vpn-connection/{vid}"))
            rec.tags = tags_to_dict(v.get("Tags"))
            rec.state_status = v.get("State", "")
            rec.description_purpose = "Site-to-Site VPN connection (hybrid connectivity)"
            rec.encryption_in_transit = True  # IPsec
            rec.encryption_in_transit_detail = "IPsec"
            rec.add_relationship("tgw", v.get("TransitGatewayId"))
            rec.notes = "connects to on-prem network (external coverage caveat)"
            rec.public_exposed = False
            rec.source_calls = ["ec2:DescribeVpnConnections"]
            out.append(rec)

        cvpn = ctx.call.call(ec2.describe_client_vpn_endpoints, account_id=ctx.account_id, region=ctx.region,
                             service="ec2", operation="DescribeClientVpnEndpoints", default={"ClientVpnEndpoints": []})
        for c in cvpn.get("ClientVpnEndpoints", []):
            cid = c["ClientVpnEndpointId"]
            rec = new_record(ctx, service="vpc", resource_type="ec2:client-vpn-endpoint",
                             resource_id=cid, arn=synth_arn("ec2", ctx.region, ctx.account_id, f"client-vpn-endpoint/{cid}"))
            rec.tags = tags_to_dict(c.get("Tags"))
            rec.state_status = c.get("Status", {}).get("Code", "")
            rec.description_purpose = "Client VPN endpoint (remote access)"
            rec.encryption_in_transit = True
            rec.dns_names = [c.get("DnsName", "")] if c.get("DnsName") else []
            add_exposure(rec, "client-vpn-endpoint")
            rec.add_relationship("vpc", c.get("VpcId"))
            rec.add_relationship("security_groups", c.get("SecurityGroupIds", []))
            rec.source_calls = ["ec2:DescribeClientVpnEndpoints"]
            out.append(rec)

        dx = ctx.client("directconnect")
        conns = ctx.call.call(dx.describe_connections, account_id=ctx.account_id, region=ctx.region,
                              service="directconnect", operation="DescribeConnections", default={"connections": []})
        for d in conns.get("connections", []):
            did = d["connectionId"]
            rec = new_record(ctx, service="directconnect", resource_type="directconnect:connection",
                             resource_id=did, arn=synth_arn("directconnect", ctx.region, ctx.account_id, f"dxcon/{did}"),
                             name=d.get("connectionName", ""))
            rec.tags = tags_to_dict(d.get("tags"))
            rec.state_status = d.get("connectionState", "")
            rec.description_purpose = "Direct Connect connection (hybrid connectivity)"
            rec.notes = "connects to on-prem network (external coverage caveat)"
            rec.encryption_in_transit = bool(d.get("encryptionMode") and d.get("encryptionMode") != "no_encrypt")
            rec.encryption_in_transit_detail = d.get("encryptionMode", "")
            rec.public_exposed = False
            rec.source_calls = ["directconnect:DescribeConnections"]
            out.append(rec)

        return out
