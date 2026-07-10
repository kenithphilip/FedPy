"""Region discovery, unused-region detection, and the Regions Coverage report.

Enabled regions are auto-discovered per account (never hardcoded). A cheap
per-region indicator probe then decides whether a region is *in use*; empty
regions are recorded but skipped for full collection unless the user forces them.

CLI/config controls (CLI takes precedence):
- ``regions`` (allowlist), ``exclude_regions``
- ``all_regions`` — force full collection of every enabled region (incl. empty)
- ``include_empty_regions`` — collect empty regions too (record either way)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from pci_inventory.auth import AccountSession
from pci_inventory.concurrency import CallContext

logger = logging.getLogger("pci_inventory.regions")


@dataclass
class RegionCoverage:
    """Coverage determination for one enabled region in one account."""

    account_id: str
    region: str
    enabled: bool
    in_use: bool
    status: str  # "included" | "excluded"
    indicator: str  # what triggered the in-use determination (or why excluded)
    probe_detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "enabled": self.enabled,
            "in_use": self.in_use,
            "status": self.status,
            "indicator": self.indicator,
            "probe_detail": self.probe_detail,
        }


def discover_enabled_regions(session: AccountSession, ctx: CallContext) -> list[str]:
    """Return the list of regions enabled for the account.

    Uses ``account:ListRegions`` (ENABLED + ENABLED_BY_DEFAULT) when available,
    falling back to ``ec2:DescribeRegions``. Returns a sorted list.
    """
    # Preferred: the Account API reflects opt-in status accurately.
    try:
        acct = session.client("account")
        regions: list[str] = []
        paginator = acct.get_paginator("list_regions")
        for page in paginator.paginate(
            RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"]
        ):
            for r in page.get("Regions", []):
                regions.append(r["RegionName"])
        if regions:
            return sorted(regions)
    except Exception as exc:  # noqa: BLE001 - fall back to EC2
        logger.debug("account:ListRegions unavailable (%s); falling back to ec2", exc)

    # Fallback: EC2 DescribeRegions (only returns regions usable by the caller).
    ec2 = session.client("ec2", region="us-east-1")
    resp = ctx.call(
        ec2.describe_regions,
        account_id=session.account_id, region="us-east-1", service="ec2",
        operation="DescribeRegions", default={"Regions": []},
        AllRegions=False,
    )
    return sorted(r["RegionName"] for r in resp.get("Regions", []))


def _probe_region(session: AccountSession, ctx: CallContext, region: str) -> tuple[bool, str, dict[str, Any]]:
    """Run cheap indicator calls; return (in_use, indicator, detail).

    Indicators (any positive => in use): running/any EC2 instances, non-default
    VPCs, ENIs, RDS instances, Lambda functions. S3 is global and handled
    separately, so it is not part of the per-region probe.
    """
    detail: dict[str, Any] = {}

    ec2 = session.client("ec2", region=region)

    # 1. EC2 instances (small page).
    inst = ctx.call(
        ec2.describe_instances,
        account_id=session.account_id, region=region, service="ec2",
        operation="DescribeInstances", default={"Reservations": []},
        MaxResults=5,
    )
    n_inst = sum(len(r.get("Instances", [])) for r in inst.get("Reservations", []))
    detail["ec2_instances"] = n_inst
    if n_inst > 0:
        return True, f"ec2:instances={n_inst}", detail

    # 2. Non-default VPCs.
    vpcs = ctx.call(
        ec2.describe_vpcs,
        account_id=session.account_id, region=region, service="ec2",
        operation="DescribeVpcs", default={"Vpcs": []},
    )
    non_default = [v for v in vpcs.get("Vpcs", []) if not v.get("IsDefault", False)]
    detail["non_default_vpcs"] = len(non_default)
    if non_default:
        return True, f"ec2:non-default-vpcs={len(non_default)}", detail

    # 3. ENIs.
    enis = ctx.call(
        ec2.describe_network_interfaces,
        account_id=session.account_id, region=region, service="ec2",
        operation="DescribeNetworkInterfaces", default={"NetworkInterfaces": []},
        MaxResults=5,
    )
    n_eni = len(enis.get("NetworkInterfaces", []))
    detail["enis"] = n_eni
    if n_eni > 0:
        return True, f"ec2:enis={n_eni}", detail

    # 4. RDS instances.
    rds = session.client("rds", region=region)
    dbs = ctx.call(
        rds.describe_db_instances,
        account_id=session.account_id, region=region, service="rds",
        operation="DescribeDBInstances", default={"DBInstances": []},
        MaxRecords=20,
    )
    n_db = len(dbs.get("DBInstances", []))
    detail["rds_instances"] = n_db
    if n_db > 0:
        return True, f"rds:instances={n_db}", detail

    # 5. Lambda functions.
    lam = session.client("lambda", region=region)
    fns = ctx.call(
        lam.list_functions,
        account_id=session.account_id, region=region, service="lambda",
        operation="ListFunctions", default={"Functions": []},
        MaxItems=5,
    )
    n_fn = len(fns.get("Functions", []))
    detail["lambda_functions"] = n_fn
    if n_fn > 0:
        return True, f"lambda:functions={n_fn}", detail

    return False, "no resources detected", detail


def _probe_region_failopen(
    session: AccountSession, ctx: CallContext, region: str
) -> tuple[bool, str, dict[str, Any]]:
    """Probe a region, failing OPEN on errors.

    If any indicator call recorded an error (throttle, AccessDenied, transient),
    we must NOT conclude the region is empty — a silently-dropped active region is
    a serious completeness gap for a QSA inventory. In that case the region is
    treated as in-use with an ``indeterminate`` indicator so it is fully
    collected and the gap is visible.
    """
    before = len(ctx.errors.errors)
    in_use, indicator, detail = _probe_region(session, ctx, region)
    errored = len(ctx.errors.errors) > before
    if not in_use and errored:
        return True, "indeterminate — probe error (failing open, region included)", detail
    return in_use, indicator, detail


def _notify_probe(
    cb: Callable[[int, int, str, bool], None] | None,
    done: int, total: int, region: str, in_use: bool,
) -> None:
    """Invoke a progress callback, suppressing any error (UI must not abort a run)."""
    if cb is None:
        return
    try:
        cb(done, total, region, in_use)
    except Exception:  # noqa: BLE001
        pass


def determine_region_coverage(
    session: AccountSession,
    ctx: CallContext,
    *,
    requested_regions: list[str],
    exclude_regions: list[str],
    all_regions: bool,
    include_empty_regions: bool,
    on_probe: Callable[[int, int, str, bool], None] | None = None,
) -> list[RegionCoverage]:
    """Compute the coverage list for an account, honoring flags.

    Resolution:
    1. Start from enabled regions; intersect with ``requested_regions`` if given;
       subtract ``exclude_regions``.
    2. If ``all_regions`` -> every candidate is included without probing.
    3. Otherwise probe each candidate; include if in use, else exclude unless
       ``include_empty_regions``.

    ``on_probe`` (optional) is called after each candidate region is resolved with
    ``(done, total, region, in_use)`` to drive a live progress display. Any
    exception it raises is suppressed so the UI can never abort a run.
    """
    enabled = discover_enabled_regions(session, ctx)
    logger.info("Account %s: %d enabled regions", session.account_id, len(enabled))

    candidates = enabled
    if requested_regions:
        allow = set(requested_regions)
        candidates = [r for r in enabled if r in allow]
        # Surface any requested-but-not-enabled regions as excluded entries.
        not_enabled = [r for r in requested_regions if r not in set(enabled)]
    else:
        not_enabled = []
    if exclude_regions:
        deny = set(exclude_regions)
        candidates = [r for r in candidates if r not in deny]

    coverage: list[RegionCoverage] = []

    total = len(candidates)
    for idx, region in enumerate(candidates, start=1):
        if all_regions:
            coverage.append(RegionCoverage(
                session.account_id, region, enabled=True, in_use=True,
                status="included", indicator="--all-regions (forced)",
            ))
            _notify_probe(on_probe, idx, total, region, True)
            continue
        in_use, indicator, detail = _probe_region_failopen(session, ctx, region)
        if in_use:
            status = "included"
        else:
            status = "included" if include_empty_regions else "excluded"
        coverage.append(RegionCoverage(
            session.account_id, region, enabled=True, in_use=in_use,
            status=status, indicator=indicator, probe_detail=detail,
        ))
        _notify_probe(on_probe, idx, total, region, in_use)

    # Record excluded-by-flag and not-enabled regions for transparency.
    for region in exclude_regions:
        if region in set(enabled):
            coverage.append(RegionCoverage(
                session.account_id, region, enabled=True, in_use=False,
                status="excluded", indicator="--exclude-regions (forced)",
            ))
    for region in not_enabled:
        coverage.append(RegionCoverage(
            session.account_id, region, enabled=False, in_use=False,
            status="excluded", indicator="requested but not enabled for account",
        ))

    included = [c.region for c in coverage if c.status == "included"]
    logger.info("Account %s: %d regions included for full collection",
                session.account_id, len(included))
    return coverage


def included_regions(coverage: list[RegionCoverage], account_id: str) -> list[str]:
    """Return the sorted list of included regions for an account."""
    return sorted({c.region for c in coverage
                   if c.account_id == account_id and c.status == "included" and c.enabled})
