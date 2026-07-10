"""Read-only gap re-fetch for precise NACL + route-table data.

The Stage 1 artifact stores SG rules as parseable strings (sufficient) but stores
NACL entries only as a truncated free-text note and route tables without the
exact destination-CIDR→target association. To layer route ∧ SG ∧ NACL precisely
(see ``research/06``), Stage 2 re-fetches **only** ``DescribeNetworkAcls`` and
``DescribeRouteTables`` — read-only, for the (account, region) pairs that were in
the Stage 1 collection. Nothing else is re-collected; the run stays read-only.

If credentials/regions are unavailable (e.g. analysing an artifact offline), the
fetch degrades gracefully: the engine falls back to the artifact's lossy data and
lowers path confidence with a recorded note.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from pci_inventory.concurrency import CallContext, WorkUnit, run_work_units

logger = logging.getLogger("pci_inventory.scope.gapfetch")


@dataclass
class NaclRule:
    """One NACL entry (stateless)."""

    rule_number: int
    protocol: str  # "-1" all, "6" tcp, "17" udp
    egress: bool
    action: str  # allow | deny
    cidr: str
    from_port: int | None
    to_port: int | None


@dataclass
class Nacl:
    nacl_id: str
    vpc_id: str
    is_default: bool
    subnet_ids: list[str] = field(default_factory=list)
    inbound: list[NaclRule] = field(default_factory=list)
    outbound: list[NaclRule] = field(default_factory=list)


@dataclass
class Route:
    dest_cidr: str  # may be "" for prefix-list routes
    dest_prefix_list: str
    target: str  # igw-/nat-/pcx-/tgw-/eni-/local/...
    state: str  # active | blackhole


@dataclass
class RouteTable:
    rt_id: str
    vpc_id: str
    subnet_ids: list[str] = field(default_factory=list)
    is_main: bool = False
    routes: list[Route] = field(default_factory=list)


@dataclass
class NetworkData:
    """Precise network layer data, keyed for the reachability engine."""

    nacls_by_subnet: dict[str, Nacl] = field(default_factory=dict)
    route_tables_by_subnet: dict[str, RouteTable] = field(default_factory=dict)
    main_rt_by_vpc: dict[str, RouteTable] = field(default_factory=dict)
    fetched: bool = False  # True if live data was obtained; False = artifact fallback
    notes: list[str] = field(default_factory=list)

    def route_table_for_subnet(self, subnet_id: str, vpc_id: str) -> RouteTable | None:
        return self.route_tables_by_subnet.get(subnet_id) or self.main_rt_by_vpc.get(vpc_id)


def _parse_nacl(nacl: dict[str, Any]) -> Nacl | None:
    if not nacl.get("NetworkAclId"):
        return None  # malformed entry — skip, don't abort the region (D-B2)
    obj = Nacl(
        nacl_id=nacl["NetworkAclId"],
        vpc_id=nacl.get("VpcId", ""),
        is_default=bool(nacl.get("IsDefault")),
        subnet_ids=[a.get("SubnetId") for a in nacl.get("Associations", []) if a.get("SubnetId")],
    )
    for e in nacl.get("Entries", []):
        pr = e.get("PortRange", {})
        rule = NaclRule(
            rule_number=e.get("RuleNumber", 0),
            protocol=str(e.get("Protocol", "-1")),
            egress=bool(e.get("Egress")),
            action=e.get("RuleAction", "deny"),
            cidr=e.get("CidrBlock", e.get("Ipv6CidrBlock", "")),
            from_port=pr.get("From"),
            to_port=pr.get("To"),
        )
        (obj.outbound if rule.egress else obj.inbound).append(rule)
    obj.inbound.sort(key=lambda r: r.rule_number)
    obj.outbound.sort(key=lambda r: r.rule_number)
    return obj


def _parse_route_table(rt: dict[str, Any]) -> RouteTable | None:
    if not rt.get("RouteTableId"):
        return None  # malformed entry — skip (D-B2)
    obj = RouteTable(
        rt_id=rt["RouteTableId"],
        vpc_id=rt.get("VpcId", ""),
        subnet_ids=[a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")],
        is_main=any(a.get("Main") for a in rt.get("Associations", [])),
    )
    for r in rt.get("Routes", []):
        target = (r.get("GatewayId") or r.get("NatGatewayId") or r.get("TransitGatewayId")
                  or r.get("VpcPeeringConnectionId") or r.get("NetworkInterfaceId")
                  or r.get("InstanceId") or r.get("CarrierGatewayId")
                  or r.get("LocalGatewayId") or r.get("CoreNetworkArn") or "")
        obj.routes.append(Route(
            dest_cidr=r.get("DestinationCidrBlock", r.get("DestinationIpv6CidrBlock", "")),
            dest_prefix_list=r.get("DestinationPrefixListId", ""),
            target=target,
            state=r.get("State", "active"),
        ))
    return obj


def fetch_network_data(
    index,
    session_factory: Callable[[str], Any] | None,
    call_ctx: CallContext | None = None,
    max_workers: int = 8,
    *,
    on_unit_start: Callable[[Any], None] | None = None,
    on_unit_end: Callable[[Any], None] | None = None,
    on_unit_done: Callable[[int, int, Any, int], None] | None = None,
) -> NetworkData:
    """Re-fetch NACLs + route tables read-only for the artifact's in-use regions.

    Reuses Stage 1 infrastructure (re-audit S3 D-I1/I2): every ``DescribeNetworkAcls``
    / ``DescribeRouteTables`` call goes through the rate-limited, error-capturing
    :class:`~pci_inventory.concurrency.CallContext`, and the (account, region) work
    units run on the bounded :func:`run_work_units` thread pool — so a wide
    multi-region account cannot throttle the run, and any failure lands in the
    structured error report instead of a free-text note.

    ``session_factory(account_id) -> AccountSession | None`` supplies an
    authenticated session per account (None → artifact fallback). Degrades
    gracefully when no credentials are available.
    """
    data = NetworkData()
    pairs = index.regions_in_use()
    if not pairs:
        data.notes.append("no in-use regions recorded in artifact; using artifact fallback")
        return data
    if session_factory is None:
        data.notes.append("no credentials available; NACL/route precision unavailable (artifact fallback)")
        return data

    # A CallContext is required to reuse the rate limiter + error capture. If the
    # caller didn't supply one, build a conservative default.
    if call_ctx is None:
        from pci_inventory.concurrency import (
            ErrorCollector,
            ServiceThrottleGate,
            TokenBucket,
        )
        call_ctx = CallContext(TokenBucket(40.0, 80.0),
                               ServiceThrottleGate(["ec2"], 2, 6), ErrorCollector())

    by_account: dict[str, set[str]] = {}
    for acct, region in pairs:
        by_account.setdefault(acct, set()).add(region)

    # Resolve one session per account once (assume-role/multi-account supported by
    # the supplied factory). Sessions are thread-safe handles; clients are made
    # per-thread inside AccountSession.client.
    sessions: dict[str, Any] = {}
    for account_id in sorted(by_account):
        try:
            s = session_factory(account_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not build session for %s: %s", account_id, exc)
            s = None
        if s is None:
            data.notes.append(f"account {account_id}: no session; artifact fallback")
            continue
        sessions[account_id] = s

    # Merge per-unit results under a lock (run_work_units returns lists; we mutate
    # the shared NetworkData maps here in the unit fn under this lock).
    lock = threading.Lock()
    fetched_flag = {"any": False}

    def make_unit(account_id: str, region: str) -> WorkUnit:
        session = sessions[account_id]

        def _run() -> list[Any]:
            ec2 = session.client("ec2", region=region)
            nacls = list(call_ctx.paginate(
                ec2, "describe_network_acls", account_id=account_id, region=region,
                service="ec2", result_key="NetworkAcls"))
            rts = list(call_ctx.paginate(
                ec2, "describe_route_tables", account_id=account_id, region=region,
                service="ec2", result_key="RouteTables"))
            with lock:
                for nacl in nacls:
                    parsed = _parse_nacl(nacl)
                    if not parsed:
                        continue
                    for sid in parsed.subnet_ids:
                        data.nacls_by_subnet[sid] = parsed
                for rt in rts:
                    parsed_rt = _parse_route_table(rt)
                    if not parsed_rt:
                        continue
                    for sid in parsed_rt.subnet_ids:
                        data.route_tables_by_subnet[sid] = parsed_rt
                    if parsed_rt.is_main:
                        data.main_rt_by_vpc[parsed_rt.vpc_id] = parsed_rt
                if nacls or rts:
                    fetched_flag["any"] = True
            return []

        return WorkUnit(account_id=account_id, region=region, service="ec2",
                        label="gap-fetch:nacl+routes", fn=_run)

    units = [make_unit(acct, region) for acct in sorted(sessions)
             for region in sorted(by_account[acct])]
    run_work_units(units, max_workers, on_unit_start=on_unit_start,
                   on_unit_end=on_unit_end, on_unit_done=on_unit_done)

    data.fetched = fetched_flag["any"]
    if not data.fetched:
        data.notes.append("no live NACL/route data obtained; using artifact fallback (lower path confidence)")
    # Surface captured errors as notes so the operator sees gap-fetch failures.
    for err in call_ctx.errors.errors:
        if err.service == "ec2":
            data.notes.append(f"{err.account_id}/{err.region} {err.operation}: {err.error_code}")
    return data
