"""Network primitives for path evaluation: CIDR containment, port/proto overlap,
and parsing of the Stage-1 SG-rule strings.

Kept dependency-free (stdlib ``ipaddress``) and pure so the reachability engine is
unit-testable without AWS.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Conservative ephemeral port range for stateless NACL return traffic
# (research/06 §3.2). 1024-65535 covers Linux/Windows/NAT variance; the engine
# notes that a path is valid only if the NACL ephemeral rules cover the OS's
# actual range.
EPHEMERAL_LOW = 1024
EPHEMERAL_HIGH = 65535

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def cidr_contains(cidr: str, other: str) -> bool:
    """True if network ``cidr`` fully contains ``other`` (CIDR or bare IP).

    Returns False on unparseable input rather than raising.
    """
    if not cidr or not other:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if "/" in other:
            o = ipaddress.ip_network(other, strict=False)
            return o.subnet_of(net)  # type: ignore[arg-type]
        return ipaddress.ip_address(other) in net
    except (ValueError, TypeError):
        return False


def cidrs_overlap(a: str, b: str) -> bool:
    """True if two CIDRs overlap at all (either contains the other)."""
    if not a or not b:
        return False
    try:
        na = ipaddress.ip_network(a, strict=False)
        nb = ipaddress.ip_network(b, strict=False)
        return na.overlaps(nb)
    except (ValueError, TypeError):
        return False


def port_in_range(port: int, frm: int | None, to: int | None) -> bool:
    """True if a single port falls within [frm, to] (None bounds mean 'all')."""
    lo = 0 if frm is None else frm
    hi = 65535 if to is None else to
    return lo <= port <= hi


def ranges_overlap(a_lo: int, a_hi: int, b_lo: int | None, b_hi: int | None) -> bool:
    """True if [a_lo,a_hi] overlaps [b_lo,b_hi] (None bounds mean 'all')."""
    lo = 0 if b_lo is None else b_lo
    hi = 65535 if b_hi is None else b_hi
    return a_lo <= hi and lo <= a_hi


def proto_matches(rule_proto: str, want_proto: str) -> bool:
    """True if a rule's protocol matches the wanted protocol.

    ``-1`` / ``all`` matches anything. Numeric (6=tcp, 17=udp) and names are
    normalized.
    """
    rp = (rule_proto or "-1").lower()
    wp = (want_proto or "tcp").lower()
    if rp in ("-1", "all"):
        return True
    name_to_num = {"tcp": "6", "udp": "17", "icmp": "1"}
    rp_num = name_to_num.get(rp, rp)
    wp_num = name_to_num.get(wp, wp)
    return rp_num == wp_num


@dataclass
class SGRule:
    """A parsed Stage-1 security-group rule string.

    Stage 1 emits ingress/egress rules as strings of the form:
        ``"<direction> <proto>:<port|port-range|all> <cidr | sg:sg-xxxx>"``
    e.g. ``"ingress 6:443 10.0.0.0/16"``, ``"ingress -1:all 0.0.0.0/0"``,
    ``"egress 6:1024-65535 sg:sg-0abc"``.
    """

    direction: str  # ingress | egress
    proto: str  # "-1", "6", "17", ...
    port_lo: int | None
    port_hi: int | None
    cidr: str  # "" if source/dest is an SG ref
    sg_ref: str  # "" if source/dest is a CIDR


def parse_sg_rule(rule: str) -> SGRule | None:
    """Parse one Stage-1 SG rule string into an :class:`SGRule` (None if malformed)."""
    try:
        parts = rule.split()
        if len(parts) < 3:
            return None
        direction = parts[0]
        proto, _, port = parts[1].partition(":")
        target = parts[2]
        if port in ("all", ""):
            lo, hi = None, None
        elif "-" in port:
            a, b = port.split("-", 1)
            lo, hi = int(a), int(b)
        else:
            lo = hi = int(port)
        if target.startswith("sg:"):
            return SGRule(direction, proto, lo, hi, "", target[3:])
        return SGRule(direction, proto, lo, hi, target, "")
    except (ValueError, IndexError):
        return None
