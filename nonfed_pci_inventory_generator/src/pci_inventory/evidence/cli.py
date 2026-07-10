"""``pci-inventory evidence`` — Stage 3 evidence enrichment entry point.

Reads the Stage 2 ``output/inventory-scoped.json`` (falls back to Stage 1
``output/inventory.json`` with a loud banner), maps evidence to all 12 PCI DSS
v4.0.1 requirements, runs bounded read-only follow-up findings queries, computes
indicators, and writes the final consolidated workbook + CSV + JSON.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pci_inventory import __version__
from pci_inventory.progress import ProgressReporter
from pci_inventory.evidence.csv_writer import write_evidence_csv
from pci_inventory.evidence.loader import load_for_evidence
from pci_inventory.evidence.models import EvidenceThresholds
from pci_inventory.evidence.runner import build_evidence_document, run_evidence
from pci_inventory.evidence.workbook import write_evidence_workbook
from pci_inventory.utils import configure_logging, utc_now


def build_evidence_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pci-inventory evidence",
        description="PCI DSS v4.0.1 evidence enrichment (Stage 3): map evidence by requirement, "
                    "findings, indicators → final QSA workbook.")
    p.add_argument("--scoped", default="output/inventory-scoped.json",
                   help="Stage 2 scoped artifact (default: output/inventory-scoped.json).")
    p.add_argument("--inventory", default="output/inventory.json",
                   help="Stage 1 fallback if the scoped artifact is absent.")
    p.add_argument("--config", help="Stage 1 config (accounts/orgs + concurrency) reused for "
                                    "read-only follow-up findings queries.")
    p.add_argument("--thresholds", help="JSON/YAML file overriding indicator thresholds.")
    p.add_argument("--profile", help="AWS profile for the read-only follow-up queries.")
    p.add_argument("--no-findings", action="store_true",
                   help="Skip AWS follow-up findings queries; map inventory evidence + indicators only.")
    p.add_argument("--output-dir", default="output", help="Output directory (default: output).")
    p.add_argument("--no-xlsx", action="store_true", help="Skip the workbook.")
    p.add_argument("--verbose", action="store_true", help="DEBUG logging.")
    p.add_argument("--quiet", action="store_true", help="WARNING-level logging only.")
    p.add_argument("--no-progress", action="store_true",
                   help="Disable the live progress UI (logs only).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _load_thresholds(path: str | None) -> EvidenceThresholds:
    if not path:
        return EvidenceThresholds()
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    return EvidenceThresholds.from_dict(data)


def main(argv: list[str] | None = None) -> int:
    args = build_evidence_parser().parse_args(argv)
    logger = configure_logging(verbose=args.verbose, quiet=args.quiet)
    reporter = ProgressReporter.for_cli(
        quiet=args.quiet, verbose=args.verbose, no_progress=args.no_progress)
    reporter.banner(__version__, account_hint="evidence · Stage 3")
    logger.info("PCI DSS v4.0.1 evidence enrichment (Stage 3) starting — read-only")

    try:
        loaded = load_for_evidence(args.scoped, args.inventory)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 2

    thresholds = _load_thresholds(args.thresholds)

    from pci_inventory.config import load_config
    try:
        app_cfg = load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load --config (%s); using defaults.", exc)
        app_cfg = load_config(None)

    session_factory = None
    if not args.no_findings:
        from pci_inventory.scope.cli import _build_session_factory
        session_factory = _build_session_factory(app_cfg, args.profile)

    result = run_evidence(loaded, thresholds, session_factory, app_cfg, reporter)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    accts = loaded.index.accounts()
    if len(accts) == 1:
        scope_label = accts[0].get("account_id", "unknown")
    elif accts:
        scope_label = f"multi-{len(accts)}accts"
    else:
        ids = {r.get("account_id") for r in loaded.index.resources if r.get("account_id")}
        scope_label = next(iter(ids)) if len(ids) == 1 else (f"multi-{len(ids)}accts" if ids else "unknown")
    base = f"pci-dss-4.0.1-evidence_{scope_label}_{ts}"

    # Final consolidated JSON (fixed name for downstream + timestamped copy).
    doc = build_evidence_document(loaded, result)
    stable = out_dir / "inventory-evidence.json"
    stable.write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    (out_dir / f"{base}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str),
                                          encoding="utf-8")
    logger.info("Wrote consolidated evidence artifact: %s", stable)

    write_evidence_csv(result, out_dir / f"{base}.csv")

    if not args.no_xlsx:
        xlsx = write_evidence_workbook(result, out_dir / f"{base}.xlsx")
        logger.info("Wrote evidence workbook: %s", xlsx)

    _print_summary(reporter, result, out_dir)
    return 0


def _print_summary(reporter: ProgressReporter, result: Any, out_dir: Path) -> None:
    ind = result.indicators.overall
    rows = [
        ("Evidence rows", f"{len(result.rows)} across 12 requirement domains"),
        ("Encryption-at-rest", f"{ind.get('encryption_at_rest_pct')}%"),
        ("Encryption-in-transit", f"{ind.get('encryption_in_transit_pct')}%"),
        ("MFA coverage", f"{ind.get('mfa_coverage_pct')}%"),
        ("IMDSv2 enforcement", f"{ind.get('imdsv2_enforcement_pct')}%"),
        ("Public-exposed", f"{ind.get('public_exposed_count')}"),
        ("Unencrypted", f"{ind.get('unencrypted_count')}"),
        ("CloudTrail multi-region+log", f"{ind.get('cloudtrail_multiregion_logging')}"),
        ("Security findings", f"{len(result.findings.findings)}"),
    ]
    print("\n" + reporter.summary_box(rows, title="PCI DSS 4.0.1 evidence enrichment complete"))
    if result.scope_missing:
        print("  ⚠ SCOPE CONTEXT MISSING — run Stage 2 (pci-inventory scope) first; "
              "evidence is not scope-prioritized.")
    print("  Indicators ASSIST assessment — they are NOT compliance determinations. "
          "The QSA makes all determinations.")
    print(f"  Output dir: {out_dir.resolve()}")


if __name__ == "__main__":
    raise SystemExit(main())
