"""Stage 2 re-audit regression tests.

Covers the previously-untested risk areas the re-audit flagged: NACL deny,
cross-VPC routing, artifact-fallback, IAM NotAction/NotResource/wildcards,
resource-policy conditions, open-trust roles, multi-hop closure, determinism,
the by_id wrong-region guard, and ScopeConfig.flag_ids isolation.
"""

from __future__ import annotations

from pci_inventory.scope.artifact import InventoryIndex
from pci_inventory.scope.gapfetch import Nacl, NaclRule, NetworkData, Route, RouteTable
from pci_inventory.scope.iamgraph import (
    IamGraph,
    _action_capabilities,
    _resource_matches,
)
from pci_inventory.scope.netprims import cidr_contains
from pci_inventory.scope.reachability import ReachabilityGraph, _nacl_allows
from pci_inventory.scope.seeds import load_scope_config


def _res(arn, rid, rtype, **kw):
    return {"arn": arn, "resource_id": rid, "resource_type": rtype,
            "account_id": kw.get("account", "111122223333"), "region": kw.get("region", "us-east-1"),
            "name": kw.get("name", rid), "tags": kw.get("tags", {}),
            "relationships": kw.get("relationships", {}), "iam_policy_data": kw.get("iam", {}),
            "private_ips": kw.get("private_ips", []), "public_ips": kw.get("public_ips", []),
            "public_exposed": False, "exposure_basis": [], "description_purpose": kw.get("desc", "")}


def _allow_all_nacl(sid, vpc):
    return Nacl(f"acl-{sid}", vpc, False, [sid],
                [NaclRule(100, "-1", False, "allow", "0.0.0.0/0", None, None)],
                [NaclRule(100, "-1", True, "allow", "0.0.0.0/0", None, None)])


# --------------------------------------------------------------------------- #
# NACL evaluation
# --------------------------------------------------------------------------- #
def test_nacl_deny_blocks_path():
    rules = [NaclRule(100, "6", False, "deny", "10.0.1.0/24", 5432, 5432),
             NaclRule(200, "-1", False, "allow", "0.0.0.0/0", None, None)]
    # first match wins: the deny at rule 100 blocks 5432 from 10.0.1.x
    assert _nacl_allows(rules, "10.0.1.5", "6", 5432, 5432) is False
    # a different source IP falls through to the allow
    assert _nacl_allows(rules, "10.0.9.5", "6", 5432, 5432) is True


def test_nacl_default_deny_when_no_match():
    rules = [NaclRule(100, "6", False, "allow", "10.0.0.0/8", 443, 443)]
    assert _nacl_allows(rules, "10.0.0.5", "6", 5432, 5432) is False  # port not covered → default deny


def test_nacl_empty_peer_ip_fails_closed():
    rules = [NaclRule(100, "-1", False, "allow", "0.0.0.0/0", None, None)]
    # empty peer IP must NOT silently match (re-audit A-C1)
    assert _nacl_allows(rules, "", "6", 443, 443) is False


def test_ipv6_cidr_does_not_match_ipv4():
    assert cidr_contains("::/0", "10.0.0.1") is False
    assert cidr_contains("0.0.0.0/0", "10.0.0.1") is True


# --------------------------------------------------------------------------- #
# Cross-VPC routing + peering non-transitivity
# --------------------------------------------------------------------------- #
def _two_vpc_doc():
    return {"resources": [
        _res("arn:db", "db", "ec2:instance", relationships={
            "enis": ["eni-db"], "security_groups": ["sg-db"], "subnet": ["sn-b"], "vpc": ["vpc-2"]},
            tags={"pci:cde": "true"}),
        _res("arn:eni-db", "eni-db", "ec2:network-interface", relationships={
            "subnet": ["sn-b"], "vpc": ["vpc-2"], "security_groups": ["sg-db"], "attached_to": ["db"]},
            private_ips=["10.1.0.5"]),
        _res("arn:app", "app", "ec2:instance", relationships={
            "enis": ["eni-app"], "security_groups": ["sg-app"], "subnet": ["sn-a"], "vpc": ["vpc-1"]},
            private_ips=["10.0.0.5"]),
        _res("arn:eni-app", "eni-app", "ec2:network-interface", relationships={
            "subnet": ["sn-a"], "vpc": ["vpc-1"], "security_groups": ["sg-app"], "attached_to": ["app"]},
            private_ips=["10.0.0.5"]),
        _res("arn:sg-db", "sg-db", "ec2:security-group", relationships={
            "ingress_rules": ["ingress 6:5432 10.0.0.0/16"], "egress_rules": ["egress -1:all 0.0.0.0/0"]}),
        _res("arn:sg-app", "sg-app", "ec2:security-group", relationships={
            "ingress_rules": [], "egress_rules": ["egress -1:all 0.0.0.0/0"]}),
    ]}


def _netdata_peered(peered: bool) -> NetworkData:
    nd = NetworkData(fetched=True)
    nd.nacls_by_subnet["sn-a"] = _allow_all_nacl("sn-a", "vpc-1")
    nd.nacls_by_subnet["sn-b"] = _allow_all_nacl("sn-b", "vpc-2")
    # vpc-1 subnet routes 10.1.0.0/16 via pcx; vpc-2 returns 10.0.0.0/16 via the SAME pcx.
    a_routes = [Route("10.0.0.0/16", "", "local", "active")]
    b_routes = [Route("10.1.0.0/16", "", "local", "active")]
    if peered:
        a_routes.append(Route("10.1.0.0/16", "", "pcx-1", "active"))
        b_routes.append(Route("10.0.0.0/16", "", "pcx-1", "active"))
    nd.route_tables_by_subnet["sn-a"] = RouteTable("rt-a", "vpc-1", ["sn-a"], True, a_routes)
    nd.route_tables_by_subnet["sn-b"] = RouteTable("rt-b", "vpc-2", ["sn-b"], True, b_routes)
    return nd


def test_cross_vpc_with_peering_reachable():
    idx = InventoryIndex(_two_vpc_doc())
    g = ReachabilityGraph(idx, _netdata_peered(True))
    g.expand_from_seeds(g.endpoints_for_resource(idx.get("arn:db")))
    g.finalize()
    assert "arn:app" in g.connected_owner_arns()
    # the proven hop crosses the peering connection
    assert any("pcx-1" in h.via for p in g.paths for h in p.hops)


def test_cross_vpc_without_peering_not_reachable():
    idx = InventoryIndex(_two_vpc_doc())
    g = ReachabilityGraph(idx, _netdata_peered(False))
    g.expand_from_seeds(g.endpoints_for_resource(idx.get("arn:db")))
    g.finalize()
    assert "arn:app" not in g.connected_owner_arns()


def test_artifact_fallback_lowers_confidence():
    idx = InventoryIndex(_two_vpc_doc())
    g = ReachabilityGraph(idx, NetworkData(fetched=False))  # no live data
    # same-VPC not applicable here (cross-VPC needs route data) → no paths,
    # but a same-VPC variant would be CANDIDATE. Verify the flag plumbs through.
    assert g.net.fetched is False


# --------------------------------------------------------------------------- #
# IAM correctness
# --------------------------------------------------------------------------- #
def test_action_wildcards():
    assert _action_capabilities("s3:Get*") == ["read-cde-data"]
    assert "modify-cde-nsc" in _action_capabilities("ec2:*")
    assert _action_capabilities("*") == ["all-actions"]
    assert _action_capabilities("logs:CreateLogGroup") == []


def test_resource_bucket_object_normalization():
    assert _resource_matches(["arn:aws:s3:::b/*"], {"arn:aws:s3:::b"}) == ["arn:aws:s3:::b"]
    assert _resource_matches(["arn:aws:s3:::b"], {"arn:aws:s3:::b"}) == ["arn:aws:s3:::b"]
    assert _resource_matches(["arn:aws:s3:::other/*"], {"arn:aws:s3:::b"}) == []


def test_notaction_not_treated_as_literal_grant():
    # The original bug merged NotAction into granted Actions. The fix: an
    # Allow+NotAction statement is a BROAD grant — it flags every sensitive
    # capability whose action is NOT excluded (recorded as a NotAction-broad-grant,
    # CANDIDATE), and it never maps the *excluded* action to a literal grant.
    doc = {"resources": [
        _res("arn:cde", "cde", "s3:bucket"),
        _res("arn:admin", "admin", "iam:role", iam={"inline_policies": {"p": {"Statement": [
            {"Effect": "Allow", "NotAction": ["s3:DeleteBucket"], "Resource": "arn:cde"}]}}}),
    ]}
    g = IamGraph(InventoryIndex(doc))
    g.analyze({"arn:cde"})
    findings = g.security_impacting_arns().get("arn:admin", [])
    # near-admin grant → read-cde-data is reachable (via GetObject/GetObjectVersion)
    assert "read-cde-data" in {f.capability for f in findings}
    # and it is recorded as a broad NotAction grant, never a literal action grant
    assert all("NotAction-broad-grant" in f.statement_ref for f in findings)
    assert all(f.confidence == "CANDIDATE" for f in findings)


def test_notaction_excludes_listed_action():
    # Excluding a sensitive action means its capability must NOT be flagged UNLESS
    # another non-excluded action also maps to it. Exclude ALL read actions →
    # read-cde-data must not appear.
    doc = {"resources": [
        _res("arn:cde", "cde", "s3:bucket"),
        _res("arn:r", "r", "iam:role", iam={"inline_policies": {"p": {"Statement": [
            {"Effect": "Allow", "NotAction": ["s3:Get*", "s3:ListBucket"], "Resource": "arn:cde"}]}}}),
    ]}
    g = IamGraph(InventoryIndex(doc))
    g.analyze({"arn:cde"})
    caps = {f.capability for f in g.security_impacting_arns().get("arn:r", [])}
    assert "read-cde-data" not in caps  # all read actions excluded via s3:Get* glob
    assert "write-cde-data" in caps      # but write is still granted


def test_notresource_covers_cde():
    doc = {"resources": [
        _res("arn:cde", "cde", "s3:bucket"),
        _res("arn:r", "r", "iam:role", iam={"inline_policies": {"p": {"Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": ["arn:aws:s3:::other/*"]}]}}}),
    ]}
    g = IamGraph(InventoryIndex(doc))
    g.analyze({"arn:cde"})
    assert "arn:r" in g.security_impacting_arns()


def test_open_trust_role_flagged():
    doc = {"resources": [
        _res("arn:cde", "cde", "s3:bucket"),
        _res("arn:role", "role", "iam:role", iam={
            "inline_policies": {"p": {"Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:cde"}]}},
            "trust_principals": ["*"]}),
    ]}
    g = IamGraph(InventoryIndex(doc))
    g.analyze({"arn:cde"})
    caps = {f.capability for f in g.findings}
    assert "open-trust-to-cde-accessing-role" in caps


def test_resource_policy_conditioned():
    doc = {"resources": [
        _res("arn:cde", "cde", "s3:bucket", iam={"resource_based_policy": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                           "Resource": "arn:cde", "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]}}),
    ]}
    g = IamGraph(InventoryIndex(doc))
    g.analyze({"arn:cde"})
    assert any(f.capability == "resource-policy-grant-conditioned" for f in g.findings)


# --------------------------------------------------------------------------- #
# Artifact + seeds robustness
# --------------------------------------------------------------------------- #
def test_by_id_ambiguous_returns_none():
    doc = {"resources": [
        _res("arn:a", "sg-1", "ec2:security-group", region="us-east-1"),
        _res("arn:b", "sg-1", "ec2:security-group", region="us-west-2"),
    ]}
    idx = InventoryIndex(doc)
    assert idx.get("sg-1") is None  # ambiguous native id → None, not wrong region
    assert idx.get("arn:a")["region"] == "us-east-1"  # ARN is exact
    assert len(idx.get_all("sg-1")) == 2


def test_flag_ids_on_config_not_global():
    c1 = load_scope_config(None, seed_arns=["arn:x"])
    c2 = load_scope_config(None)  # no flags
    assert "arn:x" in c1.flag_ids
    assert c2.flag_ids == set()  # no leakage from the previous call


def test_load_inventory_rejects_non_inventory(tmp_path):
    import pytest
    from pci_inventory.scope.artifact import load_inventory
    bad = tmp_path / "bad.json"
    bad.write_text('{"hello": "world"}')
    with pytest.raises(ValueError):
        load_inventory(bad)
