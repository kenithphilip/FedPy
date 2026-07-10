"""Layer 1 — the reachability graph engine.

Models network endpoints (at the ENI level, where security groups + IPs attach)
and decides whether endpoint A can initiate a connection to endpoint B by
layering **all three** controls (research/06 §3):

    a permitted path A→B exists  ⇔  route(A→B) ∧ security-group(B ingress, A egress) ∧ NACL(A,B)

- **Route:** A's subnet route table must route B's IP (local within a VPC; via the
  *same* pcx/tgw target on both sides for cross-VPC); target must be active.
- **Security group (stateful):** B has an ingress rule permitting the port from A
  (A's SG id via sg-ref, or A's IP via CIDR); A's egress permits it (default
  allow-all). Return traffic is implicit. *All* source-admitting ingress rules are
  tried, not just the first.
- **NACL (stateless):** for different subnets, A-subnet outbound + B-subnet inbound
  must allow the forward flow, and ephemeral return must be allowed both ways.
  Same-subnet traffic is not NACL-filtered. Evaluated per address-family over all
  of an endpoint's IPs; an endpoint with no known IP cannot be NACL-evaluated
  (fail-closed with a note) rather than silently matching every rule.

Seeds are expanded in BOTH directions, and **multi-hop** chains are composed via a
transitive closure (BFS) over proven single-hop edges — so a host behind a bastion
that reaches the CDE is itself connected-to. Every recorded path carries its
concrete hops + ports, because the QSA needs the proof, not just the verdict.

Honesty limits (also in output caveats): this proves *configuration* connectivity,
not live reachability or data flow. TGW intra-fabric routing (route-table
associations) and dynamic prefix lists are approximated and noted; assumed legs
(missing egress rules / missing NACL data) lower a path to CANDIDATE.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from pci_inventory.scope.artifact import InventoryIndex
from pci_inventory.scope.gapfetch import NaclRule, NetworkData, RouteTable
from pci_inventory.scope.netprims import (
    EPHEMERAL_HIGH,
    EPHEMERAL_LOW,
    OPEN_CIDRS,
    SGRule,
    cidr_contains,
    parse_sg_rule,
    proto_matches,
    ranges_overlap,
)

logger = logging.getLogger("pci_inventory.scope.reachability")


@dataclass
class Endpoint:
    """A network endpoint — one ENI, with the identity it belongs to."""

    eni_id: str
    arn: str  # the ENI's own arn
    subnet_id: str
    vpc_id: str
    account_id: str
    region: str
    sg_ids: list[str]
    private_ips: list[str]
    public_ips: list[str]
    owner_arn: str  # the instance/LB/RDS/etc. this ENI serves (or the ENI itself)
    owner_type: str
    description: str = ""
    interface_type: str = ""


@dataclass
class Hop:
    """One hop in a proven path."""

    src: str  # endpoint/owner arn
    dst: str
    proto: str
    port: str
    via: str  # "local" | "peering:pcx-…" | "tgw:tgw-…" | "same-subnet"
    sg_rule: str  # the permitting SG ingress rule
    nacl_note: str  # NACL evaluation note (or "same-subnet: NACL n/a")
    assumed: bool = False  # True if any leg relied on assumed (missing) data


@dataclass
class Path:
    """A proven permitted path from a source to a CDE seed (or seed→other)."""

    path_id: str
    direction: str  # "to-cde" | "from-cde"
    source_arn: str
    target_arn: str
    hops: list[Hop] = field(default_factory=list)
    confidence: str = "DETERMINED"  # lowered to CANDIDATE on any assumed leg
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "direction": self.direction,
            "source_arn": self.source_arn,
            "target_arn": self.target_arn,
            "confidence": self.confidence,
            "hops": [vars(h) for h in self.hops],
            "notes": list(self.notes),
        }


# Resource types whose ENIs / network identity we resolve.
_ENI_TYPE = "ec2:network-interface"

# Description / interface-type hints that identify the AWS service owning a
# service-managed ENI (RDS/ELB/Lambda/VPC-endpoint/NAT all create ENIs whose
# Attachment.InstanceId is empty). Used to resolve non-EC2 seeds to endpoints
# (S1b A-H5) without a Stage 1 re-run, from the metadata Stage 1 already captured.
_SERVICE_ENI_HINTS: list[tuple[str, str]] = [
    ("rdsnetworkinterface", "rds"),
    ("elb ", "elasticloadbalancing"),
    ("elb app/", "elasticloadbalancing"),
    ("elb net/", "elasticloadbalancing"),
    ("amazon elasticache", "elasticache"),
    ("aws lambda vpc", "lambda"),
    ("vpc endpoint interface", "vpc-endpoint"),
    ("interface for nat gateway", "nat"),
    ("redshift", "redshift"),
    ("amazon redshift", "redshift"),
    ("efs mount target", "efs"),
]


def _first_str(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value not in (None, "") else ""


def _family(ip: str) -> int | None:
    try:
        return ipaddress.ip_address(ip).version
    except (ValueError, TypeError):
        return None


class ReachabilityGraph:
    """Builds endpoint topology from the artifact and finds permitted paths."""

    def __init__(self, index: InventoryIndex, netdata: NetworkData):
        self.index = index
        self.net = netdata
        self.endpoints: dict[str, Endpoint] = {}  # eni_id -> Endpoint
        self.sg_ingress: dict[str, list[SGRule]] = {}
        self.sg_egress: dict[str, list[SGRule]] = {}
        self._eni_ids_by_owner: dict[str, list[str]] = {}
        self.paths: list[Path] = []
        # Memoization caches (S3 E1): pure functions of equivalence classes.
        self._route_cache: dict[tuple, tuple[bool, str]] = {}
        self._nacl_cache: dict[tuple, tuple[bool, str]] = {}
        self._build()

    # ------------------------------------------------------------------ #
    # Build topology
    # ------------------------------------------------------------------ #
    def _build(self) -> None:
        self._parse_security_groups()
        self._build_endpoints()

    def _parse_security_groups(self) -> None:
        for sg in self.index.of_type("ec2:security-group"):
            sid = sg.get("resource_id", "")
            rels = sg.get("relationships", {}) or {}
            self.sg_ingress[sid] = [r for r in (parse_sg_rule(s) for s in rels.get("ingress_rules", [])) if r]
            self.sg_egress[sid] = [r for r in (parse_sg_rule(s) for s in rels.get("egress_rules", [])) if r]

    def _build_endpoints(self) -> None:
        # Pre-index service resources by (vpc, frozenset(sg)) and subnet for
        # service-managed ENI owner resolution (non-EC2 seeds, S1b A-H5).
        service_by_sg = self._index_service_resources()
        for eni in self.index.of_type(_ENI_TYPE):
            eid = eni.get("resource_id", "")
            rels = eni.get("relationships", {}) or {}
            subnet = _first_str(rels.get("subnet"))
            vpc = _first_str(rels.get("vpc"))
            sg_ids = self.index.relationship(eni, "security_groups")
            attached = self.index.relationship(eni, "attached_to")
            description = eni.get("description_purpose", "") or ""
            interface_type = _extract_interface_type(description)

            owner_arn, owner_type = self._resolve_owner(
                eni, attached, sg_ids, subnet, vpc, description, service_by_sg)

            ep = Endpoint(
                eni_id=eid, arn=eni.get("arn", ""), subnet_id=subnet, vpc_id=vpc,
                account_id=eni.get("account_id", ""), region=eni.get("region", ""),
                sg_ids=sg_ids, private_ips=eni.get("private_ips", []),
                public_ips=eni.get("public_ips", []), owner_arn=owner_arn,
                owner_type=owner_type, description=description, interface_type=interface_type,
            )
            self.endpoints[eid] = ep
            self._eni_ids_by_owner.setdefault(owner_arn, []).append(eid)

    def _index_service_resources(self) -> dict[str, list[dict[str, Any]]]:
        """Index candidate ENI-owning service resources by each of their SG ids."""
        by_sg: dict[str, list[dict[str, Any]]] = {}
        owner_types = ("rds:db-instance", "rds:db-cluster", "elbv2:load-balancer",
                       "elbv2:network", "elbv2:application", "elb:classic-load-balancer",
                       "lambda:function", "elasticache:cluster", "redshift:cluster",
                       "opensearch:domain", "rds:db-proxy", "efs:file-system")
        for rtype in owner_types:
            for res in self.index.of_type(rtype):
                for sg in self.index.relationship(res, "security_groups"):
                    by_sg.setdefault(sg, []).append(res)
        return by_sg

    def _resolve_owner(self, eni: dict[str, Any], attached: list[str], sg_ids: list[str],
                       subnet: str, vpc: str, description: str,
                       service_by_sg: dict[str, list[dict[str, Any]]]) -> tuple[str, str]:
        """Resolve the resource that owns an ENI (EC2 instance or service resource)."""
        # 1. Direct instance attachment (Stage 1 sets attached_to for instances).
        if attached:
            owner = self.index.get(attached[0])
            if owner:
                return owner.get("arn", eni.get("arn", "")), owner.get("resource_type", _ENI_TYPE)
        # 2. Service-managed ENI: match the owning resource by shared SG + subnet/vpc
        #    membership, constrained by the description's service hint when present.
        hint_service = _service_hint(description)
        candidates: list[dict[str, Any]] = []
        for sg in sg_ids:
            for res in service_by_sg.get(sg, []):
                candidates.append(res)
        # Narrow by service hint and subnet/vpc co-membership.
        for res in candidates:
            rtype = res.get("resource_type", "")
            if hint_service and not rtype.startswith(hint_service.split(":")[0]):
                continue
            res_subnets = set(self.index.relationship(res, "subnets")) | set(
                self.index.relationship(res, "subnet"))
            res_vpc = _first_str((res.get("relationships", {}) or {}).get("vpc"))
            if (subnet and subnet in res_subnets) or (vpc and vpc == res_vpc) or not res_subnets:
                return res.get("arn", eni.get("arn", "")), rtype
        if candidates:  # shared SG but no subnet confirmation — still the best owner
            res = candidates[0]
            return res.get("arn", eni.get("arn", "")), res.get("resource_type", _ENI_TYPE)
        # 3. Fall back to the ENI itself.
        return eni.get("arn", ""), _ENI_TYPE

    # ------------------------------------------------------------------ #
    # Seed resolution → endpoints
    # ------------------------------------------------------------------ #
    def endpoints_for_resource(self, resource: dict[str, Any]) -> list[Endpoint]:
        """Resolve a resource (instance/LB/RDS/ENI/...) to its network endpoints."""
        arn = resource.get("arn", "")
        rid = resource.get("resource_id", "")
        eni_ids = list(self._eni_ids_by_owner.get(arn, []))
        for key in ("enis", "eni"):
            for e in self.index.relationship(resource, key):
                if e in self.endpoints and e not in eni_ids:
                    eni_ids.append(e)
        if resource.get("resource_type") == _ENI_TYPE and rid in self.endpoints:
            eni_ids.append(rid)
        return [self.endpoints[e] for e in dict.fromkeys(eni_ids) if e in self.endpoints]

    def endpoints_in_network(self, *, vpcs: set[str], subnets: set[str], cidrs: list[str]) -> list[Endpoint]:
        """Endpoints whose subnet/VPC/IP falls in a declared seed network."""
        out = []
        for ep in self.endpoints.values():
            if ep.vpc_id in vpcs or ep.subnet_id in subnets:
                out.append(ep)
                continue
            if cidrs and any(cidr_contains(c, ip) for c in cidrs for ip in ep.private_ips):
                out.append(ep)
        return out

    # ------------------------------------------------------------------ #
    # Route layer (memoized by subnet/vpc equivalence class)
    # ------------------------------------------------------------------ #
    def _route_ok(self, src: Endpoint, dst: Endpoint) -> tuple[bool, str]:
        key = (src.subnet_id, src.vpc_id, dst.subnet_id, dst.vpc_id,
               tuple(dst.private_ips), tuple(src.private_ips))
        cached = self._route_cache.get(key)
        if cached is None:
            cached = self._route_ok_uncached(src, dst)
            self._route_cache[key] = cached
        return cached

    def _route_ok_uncached(self, src: Endpoint, dst: Endpoint) -> tuple[bool, str]:
        """Does src's subnet route to dst's IP? Returns (ok, via-description)."""
        if src.vpc_id and src.vpc_id == dst.vpc_id:
            # Implicit, non-removable local route covers the whole VPC CIDR.
            return True, "local"
        rt = self.net.route_table_for_subnet(src.subnet_id, src.vpc_id)
        if rt is None:
            return False, "no-route-data"
        dst_ips = dst.private_ips or []
        for route in rt.routes:
            if route.state != "active" or not route.target:
                continue
            if route.target.startswith(("pcx-", "tgw-")):
                covers = route.dest_cidr and any(cidr_contains(route.dest_cidr, ip) for ip in dst_ips)
                if not covers:
                    continue
                kind = "peering" if route.target.startswith("pcx-") else "tgw"
                dst_rt = self.net.route_table_for_subnet(dst.subnet_id, dst.vpc_id)
                # Require the return route to use the SAME target id (A-H2: no
                # accidental transitivity / mismatched fabric).
                if dst_rt and self._has_return_route(dst_rt, src.private_ips, route.target):
                    note = f"{kind}:{route.target}"
                    if kind == "tgw":
                        note += " (TGW route-table associations not verified)"
                    return True, note
                return False, f"{kind}-no-matching-return-route:{route.target}"
            if route.dest_prefix_list and not route.dest_cidr:
                # Prefix-list route — entries not resolved (A-M1). Note, don't assert.
                logger.debug("prefix-list route %s not resolved", route.dest_prefix_list)
        return False, "no-matching-route"

    @staticmethod
    def _has_return_route(rt: RouteTable, dst_ips: list[str], target: str) -> bool:
        for route in rt.routes:
            if route.state == "active" and route.target == target:
                if route.dest_cidr and any(cidr_contains(route.dest_cidr, ip) for ip in dst_ips):
                    return True
        return False

    # ------------------------------------------------------------------ #
    # Security-group layer (stateful)
    # ------------------------------------------------------------------ #
    def _sg_ingress_matches(self, dst: Endpoint, src: Endpoint) -> list[SGRule]:
        """All dst ingress rules that admit src (A-H1: try every match, not first)."""
        return [rule for sg_id in dst.sg_ids
                for rule in self.sg_ingress.get(sg_id, [])
                if self._rule_admits_source(rule, src)]

    def _rule_admits_source(self, rule: SGRule, src: Endpoint) -> bool:
        if rule.sg_ref:
            return rule.sg_ref in src.sg_ids
        if rule.cidr:
            if rule.cidr in OPEN_CIDRS:
                return True
            return any(cidr_contains(rule.cidr, ip) for ip in (src.private_ips + src.public_ips))
        return False

    def _egress_ok(self, src: Endpoint, dst: Endpoint, proto: str, lo: int, hi: int) -> bool:
        """Does src's SG egress permit reaching dst on the port?

        AWS evaluates egress as the UNION across all attached SGs — allow if *any*
        SG permits (A-M5). A new SG's implicit allow-all egress is returned by AWS,
        but if the artifact captured no egress rules for an SG we treat that SG as
        default-allow-all (correct AWS default; conservative for scope).
        """
        for sg_id in src.sg_ids:
            rules = self.sg_egress.get(sg_id, [])
            if not rules:
                return True  # this SG is default allow-all egress
            for rule in rules:
                if not proto_matches(rule.proto, proto):
                    continue
                if not ranges_overlap(lo, hi, rule.port_lo, rule.port_hi):
                    continue
                if rule.sg_ref:
                    # SG-ref egress resolves only within the same VPC (A-H3).
                    if rule.sg_ref in dst.sg_ids and src.vpc_id == dst.vpc_id:
                        return True
                    continue
                if rule.cidr and (rule.cidr in OPEN_CIDRS or any(
                        cidr_contains(rule.cidr, ip) for ip in (dst.private_ips + dst.public_ips))):
                    return True
        return False

    # ------------------------------------------------------------------ #
    # NACL layer (stateless, per address-family, all IPs)
    # ------------------------------------------------------------------ #
    def _nacl_ok(self, src: Endpoint, dst: Endpoint, proto: str, lo: int, hi: int) -> tuple[bool, str]:
        key = (src.subnet_id, dst.subnet_id, proto, lo, hi,
               tuple(src.private_ips), tuple(dst.private_ips))
        cached = self._nacl_cache.get(key)
        if cached is None:
            cached = self._nacl_ok_uncached(src, dst, proto, lo, hi)
            self._nacl_cache[key] = cached
        return cached

    def _nacl_ok_uncached(self, src: Endpoint, dst: Endpoint, proto: str, lo: int, hi: int) -> tuple[bool, str]:
        if src.subnet_id and src.subnet_id == dst.subnet_id:
            return True, "same-subnet: NACL n/a"
        out_nacl = self.net.nacls_by_subnet.get(src.subnet_id)
        in_nacl = self.net.nacls_by_subnet.get(dst.subnet_id)
        if out_nacl is None or in_nacl is None:
            # Default NACL is allow-all; absence of data is an ASSUMED allow.
            return True, "ASSUMED: NACL data unavailable — default-allow assumed (verify)"

        # Choose a representative IP pair per address family; an endpoint with no
        # known IP cannot be NACL-evaluated → fail-closed (A-C1) rather than
        # silently matching every CIDR.
        pairs = _family_ip_pairs(src.private_ips, dst.private_ips)
        if not pairs:
            return False, f"{out_nacl.nacl_id}/{in_nacl.nacl_id}: no IP to evaluate NACL (fail-closed)"

        for src_ip, dst_ip in pairs:
            if not _nacl_allows(out_nacl.outbound, dst_ip, proto, lo, hi):
                return False, f"{out_nacl.nacl_id} outbound denies {proto}:{lo}-{hi}→{dst_ip}"
            if not _nacl_allows(in_nacl.inbound, src_ip, proto, lo, hi):
                return False, f"{in_nacl.nacl_id} inbound denies {proto}:{lo}-{hi} from {src_ip}"
            # Stateless return (skip port logic for ICMP, which has no ports).
            if proto not in ("1", "icmp", "58"):
                if not _nacl_allows(in_nacl.outbound, src_ip, proto, EPHEMERAL_LOW, EPHEMERAL_HIGH):
                    return False, f"{in_nacl.nacl_id} outbound denies ephemeral return to {src_ip}"
                if not _nacl_allows(out_nacl.inbound, dst_ip, proto, EPHEMERAL_LOW, EPHEMERAL_HIGH):
                    return False, f"{out_nacl.nacl_id} inbound denies ephemeral return from {dst_ip}"
        return True, f"{out_nacl.nacl_id}/{in_nacl.nacl_id} allow (incl. ephemeral {EPHEMERAL_LOW}-{EPHEMERAL_HIGH})"

    # ------------------------------------------------------------------ #
    # Full edge evaluation
    # ------------------------------------------------------------------ #
    def edge_permitted(self, src: Endpoint, dst: Endpoint) -> Hop | None:
        """Return a Hop if src can initiate to dst, else None (route ∧ SG ∧ NACL).

        Tries every source-admitting ingress rule (A-H1) so a narrow earlier rule
        cannot shadow a permitted one. Marks the hop ``assumed`` if any leg relied
        on missing data (default-allow egress with no rules, or absent NACL data),
        which lowers the path to CANDIDATE.
        """
        if src.eni_id == dst.eni_id:
            return None
        route_ok, via = self._route_ok(src, dst)
        if not route_ok:
            return None
        rules = self._sg_ingress_matches(dst, src)
        if not rules:
            return None
        egress_assumed = not any(self.sg_egress.get(sg, []) for sg in src.sg_ids)
        for rule in rules:
            lo = 0 if rule.port_lo is None else rule.port_lo
            hi = 65535 if rule.port_hi is None else rule.port_hi
            proto = rule.proto
            if not self._egress_ok(src, dst, proto, lo, hi):
                continue
            nacl_ok, nacl_note = self._nacl_ok(src, dst, proto, lo, hi)
            if not nacl_ok:
                continue
            port_str = "all" if rule.port_lo is None else (f"{lo}" if lo == hi else f"{lo}-{hi}")
            src_label = rule.sg_ref or rule.cidr or "?"
            assumed = egress_assumed or nacl_note.startswith("ASSUMED")
            return Hop(src=src.owner_arn, dst=dst.owner_arn, proto=proto, port=port_str,
                       via=via, sg_rule=f"ingress {proto}:{port_str} from {src_label}",
                       nacl_note=nacl_note, assumed=assumed)
        return None

    # ------------------------------------------------------------------ #
    # Seed expansion (both directions) + multi-hop transitive closure
    # ------------------------------------------------------------------ #
    def expand_from_seeds(self, seed_endpoints: list[Endpoint]) -> None:
        """Find all endpoints with a permitted path to/from any seed, incl. multi-hop.

        Builds the full single-hop edge set once, then computes the transitive
        closure (BFS) so a host that reaches the CDE only through a bastion/jump
        host is itself recorded as connected-to, with the composed path (A-H4).
        """
        seed_ids = {ep.eni_id for ep in seed_endpoints}
        if not seed_ids:
            return
        # Build forward + reverse single-hop adjacency among all endpoints.
        fwd: dict[str, list[tuple[str, Hop]]] = {}
        rev: dict[str, list[tuple[str, Hop]]] = {}
        ep_ids = list(self.endpoints.keys())
        for a in ep_ids:
            for b in ep_ids:
                if a == b:
                    continue
                hop = self.edge_permitted(self.endpoints[a], self.endpoints[b])
                if hop is not None:
                    fwd.setdefault(a, []).append((b, hop))
                    rev.setdefault(b, []).append((a, hop))

        # to-cde: BFS backward from seeds over reverse edges (who can reach a seed).
        self._bfs_paths(seed_ids, rev, "to-cde")
        # from-cde: BFS forward from seeds over forward edges (what the seed reaches).
        self._bfs_paths(seed_ids, fwd, "from-cde")

    def _bfs_paths(self, seed_ids: set[str], adj: dict[str, list[tuple[str, Hop]]],
                   direction: str) -> None:
        """BFS from each seed; record the (shortest) composed path to each reached node."""
        for seed in sorted(seed_ids):
            # frontier holds (node, hop_chain). Visited per-seed to allow distinct
            # proofs from different seeds.
            visited = {seed}
            frontier: list[tuple[str, list[Hop]]] = [(seed, [])]
            while frontier:
                node, chain = frontier.pop(0)
                for nxt, hop in sorted(adj.get(node, []), key=lambda x: x[0]):
                    if nxt in visited:
                        continue
                    visited.add(nxt)
                    new_chain = chain + [hop]
                    self._record_chain(direction, seed, nxt, new_chain)
                    frontier.append((nxt, new_chain))

    def _record_chain(self, direction: str, seed_id: str, node_id: str, hops: list[Hop]) -> None:
        seed_ep = self.endpoints[seed_id]
        node_ep = self.endpoints[node_id]
        if direction == "to-cde":
            source_arn, target_arn = node_ep.owner_arn, seed_ep.owner_arn
            ordered = list(reversed(hops))  # chain was built seed→node over reverse edges
        else:
            source_arn, target_arn = seed_ep.owner_arn, node_ep.owner_arn
            ordered = hops
        if source_arn == target_arn:
            return
        assumed = any(h.assumed for h in ordered)
        confidence = "CANDIDATE" if (assumed or not self.net.fetched) else "DETERMINED"
        path = Path(path_id="", direction=direction, source_arn=source_arn,
                    target_arn=target_arn, hops=ordered, confidence=confidence)
        if len(ordered) > 1:
            path.notes.append(f"multi-hop ({len(ordered)} hops)")
        if not self.net.fetched:
            path.notes.append("NACL/route data unavailable — confidence lowered; verify with live data")
        elif assumed:
            path.notes.append("path includes an assumed leg (missing egress rules or NACL data) — confidence lowered")
        self.paths.append(path)

    def finalize(self) -> None:
        """Assign deterministic path ids after sorting (S3 D2)."""
        self.paths.sort(key=lambda p: (p.direction, p.source_arn, p.target_arn,
                                       p.hops[0].port if p.hops else "", len(p.hops)))
        for i, p in enumerate(self.paths, start=1):
            p.path_id = f"path-{i:04d}"

    # ------------------------------------------------------------------ #
    # Query helpers for the classifier
    # ------------------------------------------------------------------ #
    def connected_owner_arns(self) -> dict[str, list[str]]:
        """owner_arn -> path_ids that connect it to/from the CDE."""
        out: dict[str, list[str]] = {}
        for p in self.paths:
            owner = p.source_arn if p.direction == "to-cde" else p.target_arn
            out.setdefault(owner, []).append(p.path_id)
        return out

    def inbound_connected_arns(self) -> dict[str, list[str]]:
        """owner_arn -> path_ids where the owner can reach INTO the CDE (to-cde)."""
        out: dict[str, list[str]] = {}
        for p in self.paths:
            if p.direction == "to-cde":
                out.setdefault(p.source_arn, []).append(p.path_id)
        return out


def _extract_interface_type(description: str) -> str:
    """Pull the interface type from a Stage-1 ENI description ('ENI (interface)')."""
    if "(" in description and ")" in description:
        return description[description.rfind("(") + 1:description.rfind(")")]
    return ""


def _service_hint(description: str) -> str:
    d = (description or "").lower()
    for needle, service in _SERVICE_ENI_HINTS:
        if needle in d:
            return service
    return ""


def _family_ip_pairs(src_ips: list[str], dst_ips: list[str]) -> list[tuple[str, str]]:
    """Representative (src_ip, dst_ip) pairs per shared address family.

    Returns one pair per family present on both sides. Empty if either side has
    no usable IP (caller fails closed) — never fabricates a match.
    """
    pairs: list[tuple[str, str]] = []
    for fam in (4, 6):
        s = next((ip for ip in src_ips if _family(ip) == fam), None)
        d = next((ip for ip in dst_ips if _family(ip) == fam), None)
        if s and d:
            pairs.append((s, d))
    return pairs


def _nacl_allows(rules: list[NaclRule], peer_ip: str, proto: str, lo: int, hi: int) -> bool:
    """Evaluate ordered stateless NACL rules; first match wins; default deny.

    Only rules of the peer IP's address family are considered; a rule whose CIDR
    can't be parsed for that family is skipped. An empty ``peer_ip`` yields default
    deny (the caller guarantees a real IP via _family_ip_pairs)."""
    if not peer_ip:
        return False
    for rule in rules:
        if not proto_matches(rule.protocol, proto):
            continue
        if rule.cidr:
            # Same-family containment; cidr_contains returns False across families.
            if not cidr_contains(rule.cidr, peer_ip):
                continue
        if not ranges_overlap(lo, hi, rule.from_port, rule.to_port):
            continue
        return rule.action == "allow"
    return False  # default deny
