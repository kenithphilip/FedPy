"""Command-line interface for the PCI DSS v4.0.1 inventory generator (Stage 1).

Single-account default (ambient/SSO credentials, zero config):

    pci-inventory

Multi-account / org / region overrides are via flags and an optional config file.
Outputs (workbook + CSV + JSON) plus the stable ``output/inventory.json`` handoff
artifact land in the output directory with timestamped, account-scoped filenames.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pci_inventory import __version__
from pci_inventory.config import load_config
from pci_inventory.orchestrator import run
from pci_inventory.output import write_csv, write_inventory_json, write_workbook
from pci_inventory.progress import ProgressReporter
from pci_inventory.utils import configure_logging, utc_now


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pci-inventory",
        description="Read-only AWS asset inventory for PCI DSS v4.0.1 (Stage 1).",
    )
    p.add_argument("--config", help="Path to a YAML/JSON config (multi-account, org, tuning).")
    p.add_argument("--profile", help="AWS profile (e.g. an SSO profile) for the default account.")
    p.add_argument("--output-dir", default=None, help="Output directory (default: output/ or config).")

    # Region controls.
    p.add_argument("--regions", nargs="*", help="Allowlist of regions to scan.")
    p.add_argument("--exclude-regions", nargs="*", help="Regions to exclude.")
    p.add_argument("--all-regions", action="store_true",
                   help="Force full collection of every enabled region (incl. empty).")
    p.add_argument("--include-empty-regions", action="store_true",
                   help="Collect regions with no detected footprint too.")

    # Concurrency.
    p.add_argument("--max-workers", type=int, default=None, help="Bounded thread-pool size.")

    # Output selection.
    p.add_argument("--no-xlsx", action="store_true", help="Skip the Excel workbook.")
    p.add_argument("--no-csv", action="store_true", help="Skip the CSV export.")

    # Logging.
    p.add_argument("--verbose", action="store_true", help="DEBUG logging.")
    p.add_argument("--quiet", action="store_true", help="WARNING-level logging only.")
    p.add_argument("--no-progress", action="store_true",
                   help="Disable the live progress UI (logs only).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _apply_overrides(cfg, args: argparse.Namespace) -> None:
    """Apply CLI flag overrides onto the loaded config (CLI takes precedence)."""
    if args.regions:
        cfg.regions = args.regions
    if args.exclude_regions:
        cfg.exclude_regions = args.exclude_regions
    if args.all_regions:
        cfg.all_regions = True
    if args.include_empty_regions:
        cfg.include_empty_regions = True
    if args.max_workers:
        cfg.concurrency.max_workers = args.max_workers
    if args.output_dir:
        cfg.output_dir = args.output_dir


def _timestamp() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def _account_scope(result) -> str:
    if len(result.accounts) == 1:
        return result.accounts[0].account_id
    return f"multi-{len(result.accounts)}accts"


def main(argv: list[str] | None = None) -> int:
    import sys as _sys
    raw = list(argv) if argv is not None else _sys.argv[1:]
    # Subcommand dispatch: `pci-inventory scope ...` runs Stage 2,
    # `pci-inventory evidence ...` runs Stage 3; bare invocation (or any other
    # args) runs the Stage 1 inventory as before.
    if raw and raw[0] == "scope":
        from pci_inventory.scope.cli import main as scope_main
        return scope_main(raw[1:])
    if raw and raw[0] == "evidence":
        from pci_inventory.evidence.cli import main as evidence_main
        return evidence_main(raw[1:])

    args = build_parser().parse_args(raw)
    logger = configure_logging(verbose=args.verbose, quiet=args.quiet)

    try:
        cfg = load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load config: %s", exc)
        return 2
    _apply_overrides(cfg, args)

    command_meta = {
        "flags": {
            "regions": cfg.regions, "exclude_regions": cfg.exclude_regions,
            "all_regions": cfg.all_regions, "include_empty_regions": cfg.include_empty_regions,
            "max_workers": cfg.concurrency.max_workers, "profile": args.profile,
            "config": args.config,
        },
    }

    reporter = ProgressReporter.for_cli(
        quiet=args.quiet, verbose=args.verbose, no_progress=args.no_progress
    )
    reporter.banner(__version__, account_hint=args.profile or "")

    logger.info("PCI DSS v4.0.1 inventory generator v%s starting (read-only)", __version__)
    try:
        result = run(cfg, profile=args.profile, command_meta=command_meta, reporter=reporter)
    except Exception as exc:  # noqa: BLE001
        logger.error("Collection run failed: %s", exc)
        if args.verbose:
            raise
        return 1

    out_dir = Path(cfg.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = _timestamp()
    scope = _account_scope(result)
    base = f"pci-dss-4.0.1-inventory_{scope}_{ts}"

    reporter.phase("Writing outputs")

    # The stable handoff artifact has a FIXED name for Stages 2/3, plus a
    # timestamped copy for the record.
    json_stable = write_inventory_json(result, out_dir / "inventory.json")
    json_stamped = write_inventory_json(result, out_dir / f"{base}.json")
    logger.info("Wrote handoff artifact: %s (and %s)", json_stable, json_stamped)
    reporter.update(1, 3, "inventory.json")

    if not args.no_csv:
        csv_path = write_csv(result, out_dir / f"{base}.csv")
        logger.info("Wrote CSV: %s", csv_path)
    reporter.update(2, 3, f"{base}.csv")

    if not args.no_xlsx:
        xlsx_path = write_workbook(result, out_dir / f"{base}.xlsx")
        logger.info("Wrote workbook: %s", xlsx_path)
    reporter.update(3, 3, f"{base}.xlsx")
    reporter.finish_phase(f"output in {out_dir.resolve()}")

    stats = result.stats()
    risk = stats["risk_counts"]
    regions_included = sorted({c.region for c in result.region_coverage if c.status == "included"})

    # Boxed human summary to stdout (logs go to stderr). The summary box renders
    # plain when the live UI is disabled (pipe/redirect/--quiet), so the numbers
    # are always available regardless of terminal.
    summary = reporter.summary_box(
        [
            ("Components", f"{stats['total_resources']}"),
            ("Accounts", f"{len(result.accounts)}"),
            ("Regions", f"{len(regions_included)} ({', '.join(regions_included)})"),
            ("Duration", f"{stats['duration_seconds']}s"),
            ("Public-facing", f"{risk['public_exposed']}"),
            ("Unencrypted-at-rest", f"{risk['unencrypted_at_rest']}"),
            ("Logging-disabled", f"{risk['logging_disabled']}"),
            ("Errors captured", f"{stats['error_count']}"),
            ("Throttle events", f"{stats['throttling_events']}"),
        ],
        title="PCI DSS 4.0.1 inventory complete",
    )
    print("\n" + summary)
    if result.errors:
        print("  NOTE: see the Errors sheet / inventory.json 'errors' for access gaps.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
