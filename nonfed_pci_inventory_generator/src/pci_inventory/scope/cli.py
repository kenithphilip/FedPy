"""``pci-inventory scope`` — Stage 2 scope analysis entry point.

Reads ``output/inventory.json`` (Stage 1), expands from seeds, builds the
reachability + IAM graphs, validates segmentation, and writes
``output/inventory-scoped.json`` + the scope workbook/CSV.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from pci_inventory import __version__
from pci_inventory.progress import ProgressReporter
from pci_inventory.scope.artifact import load_inventory
from pci_inventory.scope.runner import (
    build_scoped_document,
    run_scope_analysis,
    write_scoped_json,
)
from pci_inventory.scope.seeds import load_scope_config
from pci_inventory.scope.workbook import write_scope_workbook
from pci_inventory.utils import configure_logging, utc_now


def build_scope_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pci-inventory scope",
        description="PCI DSS v4.0.1 scope analysis (Stage 2): reachability + IAM graphs + segmentation.",
    )
    p.add_argument("--inventory", default="output/inventory.json",
                   help="Path to the Stage 1 artifact (default: output/inventory.json).")
    p.add_argument("--seeds", help="Seeds config file (YAML/JSON). See docs/scope-seed-and-tagging-convention.md.")
    # Ad hoc seed flags (lowest precedence).
    p.add_argument("--seed-arn", action="append", default=[], help="Declare a CDE seed resource (repeatable).")
    p.add_argument("--seed-vpc", action="append", default=[], help="Declare a CDE seed VPC (repeatable).")
    p.add_argument("--seed-subnet", action="append", default=[], help="Declare a CDE seed subnet (repeatable).")
    p.add_argument("--seed-cidr", action="append", default=[], help="Declare a CDE seed CIDR (repeatable).")
    p.add_argument("--out-of-scope", action="append", default=[],
                   help="Assert a resource isolated; inverse-checked for a path back to the CDE (repeatable).")
    # Auth for the optional NACL/route gap-fetch.
    p.add_argument("--profile", help="AWS profile for the read-only NACL/route gap-fetch.")
    p.add_argument("--config", help="Stage 1 config (YAML/JSON: accounts/orgs + concurrency) "
                                    "reused for multi-account read-only gap-fetch.")
    p.add_argument("--no-gap-fetch", action="store_true",
                   help="Do not call AWS; use only the artifact (lower path confidence).")
    p.add_argument("--output-dir", default="output", help="Output directory (default: output).")
    p.add_argument("--no-xlsx", action="store_true", help="Skip the scope workbook.")
    p.add_argument("--verbose", action="store_true", help="DEBUG logging.")
    p.add_argument("--quiet", action="store_true", help="WARNING-level logging only.")
    p.add_argument("--no-progress", action="store_true",
                   help="Disable the live progress UI (logs only).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _build_session_factory(app_cfg, profile: str | None):
    """Build an ``account_id -> AccountSession`` factory, reusing Stage 1 auth.

    Re-audit D-I3/I4: reuse :func:`auth.resolve_sessions` / ``create_default_session``
    rather than hand-rolling boto3 sessions, and support multi-account /
    assume-role gap-fetch (any account a Stage 1 ``accounts``/``organizations``
    config can reach), not just the ambient account. Sessions are resolved once
    and cached by account id. Degrades to None (artifact fallback) per account.
    """
    from pci_inventory.auth import create_default_session, resolve_sessions

    log = logging.getLogger("pci_inventory.scope.cli")
    sessions: dict[str, Any] = {}
    try:
        if app_cfg.is_single_account_default:
            s = create_default_session(app_cfg, profile=profile)
            sessions[s.account_id] = s
        else:
            for s in resolve_sessions(app_cfg, profile=profile):
                sessions[s.account_id] = s
    except Exception as exc:  # noqa: BLE001 - degrade to artifact-only
        log.warning("Could not establish AWS sessions for gap-fetch: %s "
                    "(continuing artifact-only)", exc)

    def factory(account_id: str):
        s = sessions.get(account_id)
        if s is None:
            log.info("No session for account %s; gap-fetch will use artifact data.", account_id)
        return s

    return factory


def main(argv: list[str] | None = None) -> int:
    args = build_scope_parser().parse_args(argv)
    logger = configure_logging(verbose=args.verbose, quiet=args.quiet)
    reporter = ProgressReporter.for_cli(
        quiet=args.quiet, verbose=args.verbose, no_progress=args.no_progress)
    reporter.banner(__version__, account_hint="scope · Stage 2")
    logger.info("PCI DSS v4.0.1 scope analysis (Stage 2) starting — read-only")

    try:
        index = load_inventory(args.inventory)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 2

    scope_cfg = load_scope_config(
        args.seeds, seed_arns=args.seed_arn, seed_vpcs=args.seed_vpc,
        seed_subnets=args.seed_subnet, seed_cidrs=args.seed_cidr, out_of_scope=args.out_of_scope,
    )

    # Reuse the Stage 1 AppConfig (accounts/orgs + concurrency tuning) for the
    # read-only gap-fetch, so multi-account inventories get live NACL/route data.
    from pci_inventory.config import load_config
    try:
        app_cfg = load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load --config (%s); using defaults for gap-fetch.", exc)
        app_cfg = load_config(None)

    session_factory = None if args.no_gap_fetch else _build_session_factory(app_cfg, args.profile)
    result, graph, meta = run_scope_analysis(index, scope_cfg, session_factory, app_cfg, reporter)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    accts = index.accounts()
    if len(accts) == 1:
        scope_label = accts[0].get("account_id", "unknown")
    elif accts:
        scope_label = f"multi-{len(accts)}accts"
    else:
        # Fall back to account ids present on the resources themselves.
        ids = {r.get("account_id") for r in index.resources if r.get("account_id")}
        scope_label = next(iter(ids)) if len(ids) == 1 else (f"multi-{len(ids)}accts" if ids else "unknown")
    base = f"pci-dss-4.0.1-scope_{scope_label}_{ts}"

    # Stable handoff artifact (fixed name) + timestamped copy.
    doc = build_scoped_document(index, result, graph, meta)
    stable = write_scoped_json(doc, out_dir / "inventory-scoped.json")
    write_scoped_json(doc, out_dir / f"{base}.json")
    logger.info("Wrote scoped artifact: %s", stable)

    if not args.no_xlsx:
        xlsx = write_scope_workbook(index, result, graph, out_dir / f"{base}.xlsx")
        logger.info("Wrote scope workbook: %s", xlsx)

    _print_summary(reporter, result, meta, out_dir)
    return 0


def _print_summary(reporter: ProgressReporter, result: Any, meta: dict[str, Any], out_dir: Path) -> None:
    stats = result.stats
    by_cat = stats["by_category"]
    seg = stats["segmentation_findings"]
    rows = [
        ("By category", ", ".join(f"{k}={v}" for k, v in by_cat.items()) if isinstance(by_cat, dict) else str(by_cat)),
        ("Reachability paths", str(stats["reachability_paths"])),
        ("IAM-to-CDE findings", str(stats["iam_findings"])),
        ("Segmentation findings", str(seg)),
    ]
    print("\n" + reporter.summary_box(rows, title="PCI DSS 4.0.1 scope analysis complete"))
    if result.no_seed_mode:
        print("  ⚠ NO SEEDS PROVIDED — only candidates were flagged; nothing asserted in-scope.")
    if seg:
        print("  ⚠ Segmentation findings = declared-isolated but reachable. Review the Segmentation Findings sheet.")
    if not meta.get("gap_fetched"):
        print("  NOTE: live NACL/route data unavailable — path proofs are CANDIDATE; re-run with credentials for DETERMINED proofs.")
    print(f"  Output dir: {out_dir.resolve()}")
    print("  Caveat: the tool assists and proves connectivity; the human + QSA make the final scope determination. Isolation ≠ proof of no CHD.")


if __name__ == "__main__":
    raise SystemExit(main())
