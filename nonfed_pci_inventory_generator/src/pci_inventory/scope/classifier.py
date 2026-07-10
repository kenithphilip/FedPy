"""Layers 3 + 4 and the scope classifier (the synthesis step).

- **Layer 3 (heuristics):** internet exposure, co-location with a seed, name/tag
  signals, and "every data store is a candidate CHD location" — emitted as
  CANDIDATE signals, never assertions.
- **Layer 4 (segmentation validation):** for every resource expected out-of-scope,
  search the reachability graph for any permitted path back to the CDE. A path
  that should not exist is a FINDING.
- **Classifier:** merges seeds (Layer 0), reachability (Layer 1), IAM (Layer 2),
  and heuristics (Layer 3) into one (category, basis, confidence) per resource,
  with the strongest signal winning.

Premise (also in output caveats): the tool does not originate scope. Without
seeds it only flags candidates. Isolation evidence ≠ proof of absence of CHD.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from pci_inventory.scope.artifact import InventoryIndex
from pci_inventory.scope.iamgraph import IamGraph
from pci_inventory.scope.models import Category, Classification, Confidence, SeedKind
from pci_inventory.scope.reachability import ReachabilityGraph
from pci_inventory.scope.seeds import SeedResolver

logger = logging.getLogger("pci_inventory.scope.classifier")

# Data-store resource types — each is a candidate CHD location until a human confirms.
_DATA_STORE_TYPES = {
    "s3:bucket", "rds:db-instance", "rds:db-cluster", "dynamodb:table",
    "redshift:cluster", "redshift-serverless:namespace", "elasticache:cluster",
    "efs:file-system", "fsx:file-system", "docdb:cluster", "docdb:instance",
    "neptune:cluster", "memorydb:cluster", "timestream:database", "qldb:ledger",
    "opensearch:domain", "backup:vault", "ec2:volume", "ec2:snapshot",
}
# Name/tag substrings that hint at CHD relevance.
_NAME_SIGNALS = ("payment", "card", "pan", "cardholder", "pci", "checkout", "billing")
_ENV_SIGNALS = ("prod", "production")


@dataclass
class SegmentationFinding:
    """An unexpected permitted path/relationship between an out-of-scope resource
    and the CDE — i.e. a segmentation contradiction.

    ``kind`` distinguishes the relationship: ``inbound`` (the out-of-scope resource
    can reach INTO the CDE — the supplement's primary concern), ``outbound`` (the
    CDE reaches out to it — often expected, e.g. a log sink), or ``iam`` (an IAM
    path, not a network path). ``declared`` is True when a human explicitly
    asserted the resource out-of-scope (a stronger contradiction than a
    tool-derived out-of-scope verdict)."""

    resource_arn: str
    expected: str  # why it was believed isolated (e.g. "pci:scope=out")
    path_id: str
    path_summary: str
    kind: str = "inbound"  # inbound | outbound | iam
    declared: bool = False
    severity: str = "FINDING"

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_arn": self.resource_arn,
            "expected": self.expected,
            "path_id": self.path_id,
            "path_summary": self.path_summary,
            "kind": self.kind,
            "declared": self.declared,
            "severity": self.severity,
        }


@dataclass
class ScopeResult:
    """The full output of scope analysis (consumed by writers + Stage 3)."""

    classifications: dict[str, Classification]  # arn -> Classification
    paths: list  # list[reachability.Path]
    iam_findings: list  # list[iamgraph.IamFinding]
    segmentation_findings: list[SegmentationFinding]
    no_seed_mode: bool
    seed_conflicts: list[str]
    caveats: list[str]
    stats: dict[str, Any] = field(default_factory=dict)


class ScopeClassifier:
    def __init__(self, index: InventoryIndex, seeds: SeedResolver,
                 graph: ReachabilityGraph, iam: IamGraph):
        self.index = index
        self.seeds = seeds
        self.graph = graph
        self.iam = iam

    # ------------------------------------------------------------------ #
    def classify(self) -> ScopeResult:
        no_seed = not self.seeds.has_any_cde_seed
        classifications: dict[str, Classification] = {
            r["arn"]: Classification() for r in self.index.resources if r.get("arn")
        }

        # --- Layer 0: seeds ---
        self._apply_seeds(classifications, no_seed)

        # --- Build CDE arn set for IAM/heuristics (seeds + reachable to-cde) ---
        cde_arns = self._cde_arn_set()

        # --- Layer 1: reachability paths ---
        # Use each supporting path's own confidence (a path with an assumed leg —
        # missing egress rules / NACL data — is CANDIDATE, not DETERMINED) so the
        # classification never claims more certainty than the proof supports (C-4).
        path_conf = {p.path_id: p.confidence for p in self.graph.paths}
        connected = self.graph.connected_owner_arns()
        for owner_arn, path_ids in connected.items():
            cl = classifications.get(owner_arn)
            if cl is None:
                continue
            if no_seed:
                cl.add(Category.CONNECTED, Confidence.CANDIDATE,
                       "reachable-from-seed (NO SEEDS: candidate only)")
            else:
                determined = any(path_conf.get(pid) == "DETERMINED" for pid in path_ids)
                conf = Confidence.DETERMINED if determined else Confidence.CANDIDATE
                qualifier = "" if determined else " (assumed leg — verify)"
                cl.add(Category.CONNECTED, conf,
                       f"reachable-from-seed:{','.join(path_ids[:5])}{qualifier}")
            cl.path_ids.extend(path_ids)

        # --- Layer 2: IAM security-impacting ---
        if not no_seed:
            self.iam.analyze(cde_arns)
            for arn, findings in self.iam.security_impacting_arns().items():
                cl = classifications.get(arn)
                if cl is None:
                    continue
                top = findings[0]
                cl.add(Category.SECURITY_IMPACTING, Confidence(top.confidence)
                       if top.confidence in ("DETERMINED", "CANDIDATE") else Confidence.CANDIDATE,
                       f"iam-principal-with-cde-access:{top.capability}")
        self._apply_always_security_impacting(classifications, no_seed, cde_arns)

        # --- Layer 3: heuristics (candidates only) ---
        self._apply_heuristics(classifications, cde_arns)

        # --- Default out-of-scope vs undetermined ---
        self._finalize_unscored(classifications, no_seed)

        # --- Layer 4: segmentation validation ---
        seg_findings = self._validate_segmentation(classifications, cde_arns)

        caveats = self._caveats(no_seed)
        result = ScopeResult(
            classifications=classifications,
            paths=self.graph.paths,
            iam_findings=self.iam.findings,
            segmentation_findings=seg_findings,
            no_seed_mode=no_seed,
            seed_conflicts=self.seeds.conflicts,
            caveats=caveats,
        )
        result.stats = self._stats(result)
        return result

    # ------------------------------------------------------------------ #
    def _apply_seeds(self, cls: dict[str, Classification], no_seed: bool) -> None:
        for r in self.index.resources:
            arn = r.get("arn", "")
            seed = self.seeds.seed_for(arn)
            if seed is None:
                continue
            if seed.kind == SeedKind.CDE_RESOURCE or seed.kind == SeedKind.CDE_NETWORK:
                cls[arn].add(Category.CDE, Confidence.DETERMINED, f"seed:{seed.source}")
            elif seed.kind == SeedKind.CONNECTED:
                cls[arn].add(Category.CONNECTED, Confidence.DETERMINED, f"declared-connected:{seed.source}")
            elif seed.kind == SeedKind.OUT_OF_SCOPE:
                cls[arn].notes.append(f"declared out-of-scope ({seed.source}) — segmentation inverse-checked")

        # Network seeds: any resource in a seed VPC/subnet/CIDR is a CDE seed too.
        vpcs = set(self.seeds.cfg.cde_vpcs)
        subnets = set(self.seeds.cfg.cde_subnets)
        cidrs = list(self.seeds.cfg.cde_cidrs)
        if vpcs or subnets or cidrs:
            for r in self.index.resources:
                if self._in_seed_network(r, vpcs, subnets, cidrs):
                    cls[r["arn"]].add(Category.CDE, Confidence.DETERMINED, "seed:cde-network")

    @staticmethod
    def _in_seed_network(r: dict[str, Any], vpcs: set[str], subnets: set[str],
                         cidrs: list[str]) -> bool:
        rels = r.get("relationships", {}) or {}
        if _first(rels.get("vpc")) in vpcs or _first(rels.get("subnet")) in subnets:
            return True
        if cidrs:
            from pci_inventory.scope.netprims import cidr_contains
            for ip in r.get("private_ips", []) or []:
                if any(cidr_contains(c, ip) for c in cidrs):
                    return True
        return False

    def _cde_arn_set(self) -> set[str]:
        arns = set(self.seeds.cde_arns)
        vpcs = set(self.seeds.cfg.cde_vpcs)
        subnets = set(self.seeds.cfg.cde_subnets)
        cidrs = list(self.seeds.cfg.cde_cidrs)
        for r in self.index.resources:
            if self._in_seed_network(r, vpcs, subnets, cidrs):
                arns.add(r["arn"])
        return arns

    def _apply_always_security_impacting(self, cls: dict[str, Classification], no_seed: bool,
                                         cde_arns: set[str]) -> None:
        """Flag infra that observes/manages the CDE as security-impacting.

        Re-audit B-M2: split into two tiers to avoid pulling every unrelated key
        into PCI scope:
        - **Account-scoped** services (CloudTrail/Config/GuardDuty/Security Hub)
          genuinely observe everything in the account incl. the CDE → flagged
          DETERMINED (when seeds exist).
        - **Per-resource** items (KMS keys, R53 private zones, VPN/DX/firewalls) are
          flagged only when LINKED to a CDE resource (a CDE resource references the
          key, a firewall/VPN sits in a CDE VPC). Otherwise they are at most a
          CANDIDATE, not an assertion — a QSA rightly pushes back on a dev key
          stamped in-scope.
        """
        if no_seed:
            conf, label = Confidence.CANDIDATE, "security-impacting-infra (NO SEEDS: candidate)"
        else:
            conf, label = Confidence.DETERMINED, "security-impacting-infra"

        # Tier 1 — account-scoped observers (always flagged).
        account_scoped = {
            "cloudtrail:trail": "logging-observes-cde",
            "config:recorder": "config-observes-cde",
            "guardduty:detector": "threat-detection-observes-cde",
            "securityhub:hub": "posture-observes-cde",
        }
        for rtype, cap in account_scoped.items():
            for r in self.index.of_type(rtype):
                cls[r["arn"]].add(Category.SECURITY_IMPACTING, conf, f"{label}:{cap}")

        # Tier 2 — per-resource: only when linked to the CDE.
        cde_kms_keys = self._cde_linked_kms_keys(cde_arns)
        cde_vpcs = self._cde_vpcs(cde_arns)
        for r in self.index.of_type("kms:key"):
            if r["arn"] in cde_kms_keys or r.get("resource_id") in cde_kms_keys:
                cls[r["arn"]].add(Category.SECURITY_IMPACTING, conf, f"{label}:kms-encrypts-cde")
            else:
                cls[r["arn"]].add(Category.SECURITY_IMPACTING, Confidence.CANDIDATE,
                                  "candidate-security-impacting:kms-key-no-cde-link-found")
        # Network access paths / segmentation controls: flagged when in a CDE VPC.
        path_types = {
            "ec2:vpn-connection": "access-path-to-cde",
            "ec2:client-vpn-endpoint": "access-path-to-cde",
            "directconnect:connection": "access-path-to-cde",
            "networkfirewall:firewall": "segmentation-control",
            "route53:hosted-zone": "dns-serves-cde",
        }
        for rtype, cap in path_types.items():
            for r in self.index.of_type(rtype):
                rvpc = _first((r.get("relationships", {}) or {}).get("vpc"))
                if rvpc and rvpc in cde_vpcs:
                    cls[r["arn"]].add(Category.SECURITY_IMPACTING, conf, f"{label}:{cap}")
                else:
                    cls[r["arn"]].add(Category.SECURITY_IMPACTING, Confidence.CANDIDATE,
                                      f"candidate-security-impacting:{cap}-no-cde-vpc-link")

    def _cde_linked_kms_keys(self, cde_arns: set[str]) -> set[str]:
        """KMS key arns/ids referenced by any CDE resource's encryption config."""
        keys: set[str] = set()
        for arn in cde_arns:
            r = self.index.get(arn)
            if not r:
                continue
            for k in self.index.relationship(r, "kms_key"):
                keys.add(k)
        return keys

    def _cde_vpcs(self, cde_arns: set[str]) -> set[str]:
        vpcs: set[str] = set()
        for arn in cde_arns:
            r = self.index.get(arn)
            if r:
                v = _first((r.get("relationships", {}) or {}).get("vpc"))
                if v:
                    vpcs.add(v)
        return vpcs

    def _apply_heuristics(self, cls: dict[str, Classification], cde_arns: set[str]) -> None:
        # Seed VPCs/subnets for co-location.
        seed_vpcs = {_first((self.index.get(a) or {}).get("relationships", {}).get("vpc"))
                     for a in cde_arns}
        seed_vpcs.discard(None)
        seed_subnets = {_first((self.index.get(a) or {}).get("relationships", {}).get("subnet"))
                        for a in cde_arns}
        seed_subnets.discard(None)

        for r in self.index.resources:
            arn = r["arn"]
            cl = cls[arn]
            # Internet exposure.
            if r.get("public_exposed") is True:
                cl.add(Category.CONNECTED, Confidence.CANDIDATE,
                       "heuristic:internet-exposed (" + ";".join(r.get("exposure_basis", [])[:3]) + ")")
            # Co-location with a seed.
            rels = r.get("relationships", {}) or {}
            if seed_subnets and _first(rels.get("subnet")) in seed_subnets and arn not in cde_arns:
                cl.add(Category.CONNECTED, Confidence.CANDIDATE, "heuristic:co-located-subnet-with-seed")
            elif seed_vpcs and _first(rels.get("vpc")) in seed_vpcs and arn not in cde_arns:
                cl.add(Category.CONNECTED, Confidence.CANDIDATE, "heuristic:co-located-vpc-with-seed")
            # Name / env signals.
            name = (r.get("name", "") + " " + r.get("description_purpose", "")).lower()
            if any(s in name for s in _NAME_SIGNALS):
                cl.add(cl.category if cl.category != Category.UNDETERMINED else Category.CONNECTED,
                       Confidence.CANDIDATE, "heuristic:name-signal")
            env = (r.get("environment", "") or "").lower()
            if env in _ENV_SIGNALS:
                cl.notes.append("env=prod (review)")
            # Data store = candidate CHD location, UNLESS a human explicitly
            # classified its data as none (data-classification=none suppresses the
            # heuristic — C-5).
            if r.get("resource_type") in _DATA_STORE_TYPES and arn not in cde_arns:
                data_class = (r.get("data_classification", "") or "").lower()
                if data_class == "none":
                    cl.notes.append("data store with data-classification=none (CHD-candidate heuristic suppressed)")
                else:
                    cl.add(cl.category if cl.category != Category.UNDETERMINED else Category.UNDETERMINED,
                           Confidence.CANDIDATE, "heuristic:data-store-candidate-chd-location")

    def _finalize_unscored(self, cls: dict[str, Classification], no_seed: bool) -> None:
        gap_lossy = not self.graph.net.fetched
        for arn, cl in cls.items():
            if cl.category != Category.UNDETERMINED:
                continue
            if no_seed:
                cl.confidence = Confidence.UNDETERMINED
                cl.basis.append("no-seeds: undetermined")
            else:
                # Nothing connected it and no IAM/infra link. Out-of-scope by
                # ABSENCE of evidence is NOT a positive proof — never DETERMINED
                # (re-audit C-3). It is at most a CANDIDATE isolation claim, and
                # UNDETERMINED when the network data was lossy (the very condition
                # that should weaken an isolation claim, not strengthen it).
                cl.category = Category.OUT_OF_SCOPE
                cl.categories.add(Category.OUT_OF_SCOPE)
                cl.confidence = Confidence.UNDETERMINED if gap_lossy else Confidence.CANDIDATE
                cl.basis.append("no-path-found (isolation supported, not proof of no CHD)")
                if gap_lossy:
                    cl.notes.append("network data was lossy — isolation NOT verified; treat as undetermined")
                else:
                    cl.notes.append("isolation supported by analysis; NOT proof of absence of CHD; "
                                    "confirm with pen-test (Req 11.4.x) + CHD attestation")

    def _validate_segmentation(self, cls: dict[str, Classification],
                               cde_arns: set[str]) -> list[SegmentationFinding]:
        """Inverse check (re-audit C-1): does anything OUT of scope touch the CDE?

        Examined for **every** resource that is out-of-scope — both HUMAN-DECLARED
        (``pci:scope=out`` / config / flag) and TOOL-DERIVED (classified
        out-of-scope by analysis). For each:

        - **inbound** network path INTO the CDE → the supplement's primary
          segmentation-failure case; ranked first.
        - **outbound** path the CDE opens to it → recorded but lower priority
          (often expected, e.g. a log sink).
        - **iam** path: the resource's principal (or a principal it hosts) can act
          on the CDE without a network path.

        A declared-out resource with NO path/relationship gets an isolation-supported
        note (evidence, not a finding). Tool-derived out-of-scope with no path is
        normal isolation and is silent.
        """
        findings: list[SegmentationFinding] = []
        path_by_id = {p.path_id: p for p in self.graph.paths}  # O(1) lookup (E3)
        inbound = self.graph.inbound_connected_arns()
        outbound: dict[str, list[str]] = {}
        for p in self.graph.paths:
            if p.direction == "from-cde":
                outbound.setdefault(p.target_arn, []).append(p.path_id)
        iam_by_principal = self.iam.security_impacting_arns()

        declared_out = set(self.seeds.out_of_scope_arns)
        out_of_scope = {arn for arn, c in cls.items() if c.category == Category.OUT_OF_SCOPE}
        out_of_scope |= declared_out

        def summarize(pid: str) -> str:
            path = path_by_id.get(pid)
            if not path or not path.hops:
                return ""
            chain = " → ".join(f"{h.src}=({h.proto}:{h.port}/{h.via})=>{h.dst}" for h in path.hops)
            return f"{chain} [{path.confidence}]"

        for arn in sorted(out_of_scope):
            declared = arn in declared_out
            expected = "declared out-of-scope" if declared else "classified out-of-scope by analysis"
            in_paths = inbound.get(arn, [])
            out_paths = outbound.get(arn, [])
            iam_hits = iam_by_principal.get(arn, [])
            any_finding = False
            for pid in in_paths:
                findings.append(SegmentationFinding(
                    resource_arn=arn, expected=expected, path_id=pid,
                    path_summary=summarize(pid), kind="inbound", declared=declared))
                any_finding = True
            for pid in out_paths:
                findings.append(SegmentationFinding(
                    resource_arn=arn, expected=expected, path_id=pid,
                    path_summary=summarize(pid), kind="outbound", declared=declared,
                    severity="REVIEW"))
                any_finding = True
            for f in iam_hits:
                findings.append(SegmentationFinding(
                    resource_arn=arn, expected=expected, path_id="(iam)",
                    path_summary=f"{f.principal_arn} {f.capability} on {f.cde_resource_arn} via {f.via}",
                    kind="iam", declared=declared))
                any_finding = True
            if arn in cls:
                if any_finding:
                    cls[arn].notes.append(
                        "SEGMENTATION FINDING: out-of-scope but has a path/relationship to the CDE")
                elif declared:
                    cls[arn].notes.append(
                        "isolation supported: declared out-of-scope and no permitted path/IAM relationship "
                        "to the CDE found (does NOT prove absence of CHD)")
        # Inbound + declared first (most audit-critical), then iam, then outbound.
        kind_rank = {"inbound": 0, "iam": 1, "outbound": 2}
        findings.sort(key=lambda f: (not f.declared, kind_rank.get(f.kind, 9), f.resource_arn, f.path_id))
        return findings

    # ------------------------------------------------------------------ #
    def _caveats(self, no_seed: bool) -> list[str]:
        caveats = [
            "This tool does NOT originate PCI scope. Scope is driven by where CHD/SAD is stored/processed/transmitted — a data-content property not visible in configuration. Classifications expand from human-declared seeds; the human + QSA make the final determination.",
            "Isolation evidence proves ISOLATION, not the absence of cardholder data. An out-of-scope verdict means 'no path/relationship found', never 'contains no CHD'. Out-of-scope by absence-of-evidence is at most CANDIDATE confidence (UNDETERMINED when network data was lossy) — never a positive proof.",
            "A permitted network path requires route table AND security group AND network ACL to all allow it; same-subnet traffic is not NACL-filtered; NACLs are evaluated stateless with an assumed ephemeral range of 1024-65535.",
            "IAM analysis is a static over-approximation: it does NOT resolve SCPs, permission boundaries, condition keys, or explicit Deny statements. It flags candidate access with the granting statement, not effective access.",
            "Segmentation findings cover all out-of-scope resources (declared + tool-derived) across network paths AND IAM relationships; inbound (out-of-scope → CDE) contradictions are ranked first. Absence of findings is NOT proof of complete segmentation — penetration testing per Req 11.4.x is required.",
            "A resource may be in scope for MORE THAN ONE reason; the primary Category is the highest-ranked, with the full set in 'categories' / the secondary column.",
        ]
        if not self.graph.net.fetched:
            caveats.append("Live NACL/route-table data was unavailable; path proofs used the (lossy) artifact data and were marked CANDIDATE/UNDETERMINED. Re-run with credentials for DETERMINED path proofs.")
        if self.iam.unresolved_principals:
            caveats.append(
                f"{len(self.iam.unresolved_principals)} IAM principal(s) had attached managed policies "
                "whose documents were not in the artifact; their CDE access could not be fully evaluated "
                f"(e.g. {', '.join(self.iam.unresolved_principals[:3])}).")
        if no_seed:
            caveats.insert(0, "NO SEEDS PROVIDED — no in-scope determination was made. Only heuristic candidates are flagged. Declare seeds (docs/scope-seed-and-tagging-convention.md) for a real analysis.")
        return caveats

    def _stats(self, result: ScopeResult) -> dict[str, Any]:
        from collections import Counter
        cats = Counter(c.category.value for c in result.classifications.values())
        confs = Counter(c.confidence.value for c in result.classifications.values())
        return {
            "by_category": dict(cats),
            "by_confidence": dict(confs),
            "reachability_paths": len(result.paths),
            "iam_findings": len(result.iam_findings),
            "segmentation_findings": len(result.segmentation_findings),
            "no_seed_mode": result.no_seed_mode,
            "seed_conflicts": len(result.seed_conflicts),
        }


def _first(value: Any) -> Any:
    """First element if value is a non-empty list, else the value (or None)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value or None
