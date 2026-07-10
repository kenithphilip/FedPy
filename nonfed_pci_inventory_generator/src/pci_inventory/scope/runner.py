"""Stage 2 orchestration: load artifact → build graphs → classify → write outputs.

Ties the scope layers together and produces ``output/inventory-scoped.json`` (a
superset of inventory.json plus per-resource classification and the graph
edges/paths) for Stage 3, plus the workbook + CSV.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from pci_inventory.scope.artifact import InventoryIndex
from pci_inventory.scope.classifier import ScopeClassifier, ScopeResult
from pci_inventory.scope.gapfetch import fetch_network_data
from pci_inventory.scope.iamgraph import IamGraph
from pci_inventory.scope.models import ScopeConfig
from pci_inventory.scope.reachability import ReachabilityGraph
from pci_inventory.scope.seeds import SeedResolver

logger = logging.getLogger("pci_inventory.scope.runner")


def run_scope_analysis(
    index: InventoryIndex,
    scope_cfg: ScopeConfig,
    session_factory: Callable[[str], Any] | None = None,
    app_cfg: Any = None,
    reporter: Any = None,
) -> tuple[ScopeResult, ReachabilityGraph, dict[str, Any]]:
    """Execute the full scope analysis on a loaded inventory index.

    ``session_factory(account_id)`` supplies a read-only session for the optional
    NACL/route gap-fetch (None → artifact fallback). ``app_cfg`` (the Stage 1
    AppConfig) provides concurrency tuning so the gap-fetch reuses Stage 1's
    rate-limited, error-capturing infrastructure. ``reporter`` (optional
    :class:`~pci_inventory.progress.ProgressReporter`) drives the live UI.
    Returns the classification result, the reachability graph, and gap-fetch meta.
    """
    from pci_inventory.progress import ActivityTracker, ProgressReporter
    reporter = reporter or ProgressReporter(enabled=False, color=False)

    resolver = SeedResolver(scope_cfg, index.resources)
    logger.info("Seeds resolved: %d CDE, %d connected, %d out-of-scope (%d conflicts)",
                len(resolver.cde_arns), len(resolver.connected_arns),
                len(resolver.out_of_scope_arns), len(resolver.conflicts))

    # Build a rate-limited CallContext from Stage 1 concurrency config (S3 D-I1/I5).
    call_ctx = None
    max_workers = 8
    if app_cfg is not None:
        from pci_inventory.concurrency import (
            CallContext,
            ErrorCollector,
            ServiceThrottleGate,
            TokenBucket,
        )
        cc = app_cfg.concurrency
        call_ctx = CallContext(
            TokenBucket(cc.tokens_per_second, cc.bucket_capacity),
            ServiceThrottleGate(cc.hard_throttle_services, cc.hard_throttle_cap, cc.medium_throttle_cap),
            ErrorCollector())
        max_workers = cc.max_workers

    # Live dashboard over the read-only NACL/route gap-fetch (one unit per
    # account×region). Inert when the reporter is disabled or there is no
    # CallContext (artifact-only). The errors pane streams from call_ctx.errors.
    if call_ctx is not None and session_factory is not None:
        tracker = ActivityTracker()
        with reporter.worker_dashboard(
            tracker, call_ctx.errors, total=len(index.regions_in_use()),
            title="Gap-fetch: NACLs + route tables",
            unit_noun="account-regions", record_noun="",
        ) as dash:
            netdata = fetch_network_data(
                index, session_factory, call_ctx, max_workers,
                on_unit_start=dash.on_start, on_unit_end=dash.on_end,
                on_unit_done=dash.on_done)
            dash.set_summary("live NACL/route data" if netdata.fetched
                             else "artifact fallback (no live data)")
    else:
        netdata = fetch_network_data(index, session_factory, call_ctx, max_workers)
    graph = ReachabilityGraph(index, netdata)

    # Expand from every CDE seed endpoint (resources + declared networks).
    reporter.phase("Building reachability graph")
    seed_endpoints = []
    for arn in sorted(resolver.cde_arns):  # sorted for deterministic seed order
        res = index.get(arn)
        if res:
            seed_endpoints.append(res)
    seed_eps = []
    for res in seed_endpoints:
        seed_eps.extend(graph.endpoints_for_resource(res))
    # Network seeds → endpoints in those networks.
    seed_eps.extend(graph.endpoints_in_network(
        vpcs=set(scope_cfg.cde_vpcs), subnets=set(scope_cfg.cde_subnets),
        cidrs=list(scope_cfg.cde_cidrs)))
    # Dedup endpoints by eni id.
    uniq = {ep.eni_id: ep for ep in seed_eps}
    logger.info("Expanding reachability from %d seed endpoints", len(uniq))
    graph.expand_from_seeds(list(uniq.values()))
    graph.finalize()  # assign deterministic path ids after sorting
    reporter.finish_phase(f"{len(graph.paths)} path(s) from {len(uniq)} seed endpoint(s)")

    reporter.phase("Classifying scope + IAM graph + segmentation")
    iam = IamGraph(index)
    result = ScopeClassifier(index, resolver, graph, iam).classify()
    meta = {"gap_fetched": netdata.fetched, "gap_notes": netdata.notes}
    logger.info("Scope analysis: %s", result.stats)
    st = result.stats
    reporter.finish_phase(
        f"{st['iam_findings']} IAM finding(s), {st['segmentation_findings']} segmentation finding(s)")
    return result, graph, meta


def build_scoped_document(index: InventoryIndex, result: ScopeResult,
                          graph: ReachabilityGraph, meta: dict[str, Any]) -> dict[str, Any]:
    """Build the inventory-scoped.json document (superset of inventory.json)."""
    # Start from the original document so Stage 1 data is preserved verbatim.
    doc = dict(index.document)
    doc["scope_schema_version"] = "1.0.0"

    # Enrich each resource in place with its classification (also update the
    # pci_scope / pci_scope_basis columns so the model stays the single contract).
    enriched: list[dict[str, Any]] = []
    for r in index.resources:
        arn = r.get("arn", "")
        cl = result.classifications.get(arn)
        r2 = dict(r)
        if cl is not None:
            r2["pci_scope"] = cl.category.value
            r2["pci_scope_basis"] = "; ".join(cl.basis)
            r2["scope"] = cl.to_dict()
        enriched.append(r2)
    doc["resources"] = enriched

    doc["scope_analysis"] = {
        "no_seed_mode": result.no_seed_mode,
        "seed_conflicts": result.seed_conflicts,
        "gap_fetch": meta,
        "caveats": result.caveats,
        "stats": result.stats,
        "reachability_paths": [p.to_dict() for p in graph.paths],
        "iam_findings": [f.to_dict() for f in result.iam_findings],
        "segmentation_findings": [f.to_dict() for f in result.segmentation_findings],
    }
    return doc


def write_scoped_json(doc: dict[str, Any], path: str | Path) -> Path:
    """Persist the scoped artifact for Stage 3."""
    import json
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return out
