"""Tests for the concurrency primitives — focused on the throttle gate.

The headline test reproduces the production deadlock: a collector that makes a
gated call **while already holding the same gate** (nested pagination, e.g.
Organizations ``list_policies`` → ``describe_policy``). With a plain
non-reentrant semaphore at cap 1 the nested acquire self-blocks forever; the
per-thread-reentrant gate must let it through while still capping *distinct*
threads.
"""

from __future__ import annotations

import threading
import time

import pytest

from pci_inventory.concurrency import ServiceThrottleGate


def test_nested_same_thread_acquire_does_not_deadlock() -> None:
    # cap=1 is the worst case: a non-reentrant gate would self-block on the
    # nested acquire. A 2s budget is generous; a real deadlock never returns.
    gate = ServiceThrottleGate(["organizations"], hard_cap=1, medium_cap=1)
    g = gate.gate_for("organizations")
    assert g is not None

    done = threading.Event()

    def worker() -> None:
        g.acquire()          # outer (paginate holds the gate)
        try:
            g.acquire()      # nested (describe_policy while iterating)
            try:
                pass
            finally:
                g.release()
        finally:
            g.release()
        done.set()

    t = threading.Thread(target=worker)
    t.start()
    t.join(timeout=2.0)
    assert done.is_set(), "nested same-thread acquire deadlocked"


def test_cross_thread_cap_still_enforced() -> None:
    # Distinct threads must still be limited to `hard_cap` concurrent holders.
    gate = ServiceThrottleGate(["iam"], hard_cap=2, medium_cap=2)
    g = gate.gate_for("iam")
    assert g is not None

    concurrent = 0
    peak = 0
    lock = threading.Lock()
    release = threading.Event()

    def worker() -> None:
        nonlocal concurrent, peak
        g.acquire()
        try:
            with lock:
                concurrent += 1
                peak = max(peak, concurrent)
            release.wait(timeout=2.0)
        finally:
            with lock:
                concurrent -= 1
            g.release()

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    # Give them a moment to pile up against the cap, then let go.
    time.sleep(0.3)
    with lock:
        observed_peak = peak
    release.set()
    for t in threads:
        t.join(timeout=2.0)

    assert observed_peak <= 2, f"gate exceeded cap: peak={observed_peak}"


def test_release_without_acquire_is_safe() -> None:
    # Defensive: an unbalanced release must not corrupt the underlying semaphore.
    gate = ServiceThrottleGate(["config"], hard_cap=1, medium_cap=1)
    g = gate.gate_for("config")
    assert g is not None
    g.release()  # no-op, must not raise or inflate permits
    # The cap is still 1: acquire once succeeds, and a nested acquire is free.
    g.acquire()
    g.acquire()
    g.release()
    g.release()


def test_uncapped_services_have_no_gate() -> None:
    gate = ServiceThrottleGate(["iam"], hard_cap=2, medium_cap=6)
    assert gate.gate_for("route53") is None  # neither hard nor medium
    assert gate.gate_for("ec2") is not None   # medium
    assert gate.gate_for("iam") is not None   # hard


@pytest.mark.parametrize("svc", ["organizations", "config", "cloudtrail", "apigateway", "apigatewayv2", "iam"])
def test_all_hard_services_share_one_reentrant_gate(svc: str) -> None:
    gate = ServiceThrottleGate(
        ["iam", "organizations", "config", "apigateway", "apigatewayv2", "cloudtrail"],
        hard_cap=2, medium_cap=6,
    )
    assert gate.gate_for(svc) is gate.gate_for("iam")
