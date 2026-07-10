"""Run orchestration: resolve sessions, determine region coverage, build and run
work units across (account × region × collector), and assemble the RunResult.

Global collectors run once per account (region label GLOBAL); regional collectors
run once per included region. All work units share the bounded thread pool, the
rate limiter, the per-service throttle gate, and the error collector.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from botocore.exceptions import UnknownServiceError

from pci_inventory.auth import AccountSession, resolve_sessions
from pci_inventory.collectors import REGISTRY
from pci_inventory.collectors.base import CollectorContext
from pci_inventory.concurrency import (
    CallContext,
    CollectionError,
    ErrorCollector,
    ServiceThrottleGate,
    TokenBucket,
    WorkUnit,
    run_work_units,
)
from pci_inventory.config import AppConfig
from pci_inventory.output.result import AccountInfo, RunResult
from pci_inventory.progress import ActivityTracker, ProgressReporter
from pci_inventory.regions import determine_region_coverage, included_regions

logger = logging.getLogger("pci_inventory.orchestrator")


def run(
    cfg: AppConfig,
    profile: str | None = None,
    command_meta: dict[str, Any] | None = None,
    reporter: ProgressReporter | None = None,
) -> RunResult:
    """Execute a full collection run and return the assembled result."""
    start = time.monotonic()
    # A disabled reporter is a safe no-op, so the rest of the function need not
    # branch on whether a live UI was requested.
    reporter = reporter or ProgressReporter(enabled=False, color=False)

    bucket = TokenBucket(cfg.concurrency.tokens_per_second, cfg.concurrency.bucket_capacity)
    gate = ServiceThrottleGate(
        cfg.concurrency.hard_throttle_services,
        cfg.concurrency.hard_throttle_cap,
        cfg.concurrency.medium_throttle_cap,
    )
    errors = ErrorCollector()
    call_ctx = CallContext(bucket=bucket, gate=gate, errors=errors)

    result = RunResult(command=command_meta or {})

    # 1. Resolve account sessions (single-account default or multi via config).
    sessions = resolve_sessions(cfg, profile=profile)
    result.accounts = [AccountInfo(s.account_id, s.alias, s.via) for s in sessions]

    # 2. Determine region coverage per account (probe unless forced).
    reporter.phase("Discovering active regions")
    for session in sessions:
        coverage = determine_region_coverage(
            session, call_ctx,
            requested_regions=cfg.regions,
            exclude_regions=cfg.exclude_regions,
            all_regions=cfg.all_regions,
            include_empty_regions=cfg.include_empty_regions,
            on_probe=lambda done, total, region, in_use: reporter.update(
                done, total, f"{region} {'· in use' if in_use else '· empty'}"
            ),
        )
        result.region_coverage.extend(coverage)
    included_count = sum(1 for c in result.region_coverage if c.status == "included")
    reporter.finish_phase(f"{included_count} region(s) in scope for collection")

    # 3. Build work units.
    units = _build_work_units(cfg, call_ctx, sessions, result)
    logger.info("Built %d work units across %d account(s)", len(units), len(sessions))

    # 4. Run with bounded concurrency; collect records.
    # A live multi-worker dashboard shows what each worker is doing and streams
    # captured errors in real time. The handle is inert when the UI is disabled,
    # and the context manager guarantees logging is restored on any exit.
    tracker = ActivityTracker()
    with reporter.worker_dashboard(tracker, errors, total=len(units)) as dash:
        records = run_work_units(
            units, cfg.concurrency.max_workers,
            on_unit_start=dash.on_start,
            on_unit_end=dash.on_end,
            on_unit_done=dash.on_done,
        )
        dash.set_summary(f"{len(records)} components across {len(sessions)} account(s)")
    result.records = records

    # 5. Finalize stats.
    result.errors = errors.errors
    result.throttle_events = errors.throttle_events
    result.duration_seconds = time.monotonic() - start
    logger.info("Collected %d resources, %d errors, %d throttle events in %.1fs",
                len(records), len(result.errors), result.throttle_events, result.duration_seconds)
    return result


def _build_work_units(cfg: AppConfig, call_ctx: CallContext, sessions: list[AccountSession],
                      result: RunResult) -> list[WorkUnit]:
    """Create one work unit per (collector × account × applicable region)."""
    units: list[WorkUnit] = []
    global_collectors = [c for c in REGISTRY if c.is_global]
    regional_collectors = [c for c in REGISTRY if not c.is_global]

    for session in sessions:
        regions = included_regions(result.region_coverage, session.account_id)

        # Global collectors: once per account.
        for collector in global_collectors:
            ctx = CollectorContext(session=session, region="GLOBAL", call=call_ctx, config=cfg)
            units.append(_make_unit(collector, ctx, session.account_id, "GLOBAL"))

        # Regional collectors: once per included region.
        for region in regions:
            ctx = CollectorContext(session=session, region=region, call=call_ctx, config=cfg)
            for collector in regional_collectors:
                units.append(_make_unit(collector, ctx, session.account_id, region))

    return units


def _make_unit(collector: Any, ctx: CollectorContext, account_id: str, region: str) -> WorkUnit:
    label = f"{type(collector).__name__}"

    def _run() -> list[Any]:
        try:
            records = collector.collect(ctx) or []
        except UnknownServiceError:
            # The installed AWS SDK no longer knows this service — almost always a
            # service AWS has deprecated/removed (e.g. QLDB, end-of-support
            # 2025-07-31). There is nothing to collect; record it once as a benign
            # gap (visible in the Errors sheet, never silently absent) and move on
            # rather than letting it raise per-region with the full service dump.
            ctx.call.errors.record(
                CollectionError(account_id, region, collector.service, "client",
                                "UnknownServiceError",
                                f"AWS SDK has no '{collector.service}' service "
                                "(deprecated/removed); skipped")
            )
            return []
        # Apply common derivations every record needs.
        return [collector._finalize(ctx, r) for r in records]

    return WorkUnit(account_id=account_id, region=region, service=collector.service,
                    label=label, fn=_run)
