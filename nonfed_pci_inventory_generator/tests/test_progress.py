"""Offline tests for the interactive progress UI (no AWS access required).

These verify the two guarantees that matter for a QSA tool: (1) the live UI is a
complete no-op when output is not an interactive TTY (piped/redirected/quiet), so
it never corrupts logs or machine-readable output; and (2) when enabled, the
banner/summary boxes are drawn flush (every line the same display width) and the
callback plumbing tolerates a misbehaving callback.
"""

from __future__ import annotations

import io
import logging
import os
import re

import pci_inventory.progress as progress_mod
from pci_inventory.concurrency import (
    CollectionError,
    ErrorCollector,
    WorkUnit,
    run_work_units,
)
from pci_inventory.progress import (
    ActivityTracker,
    ProgressReporter,
    _Ansi,
    _clip_visible,
    _Dashboard,
    _visible_len,
)


def _plain_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln.strip()]


def test_disabled_reporter_writes_nothing() -> None:
    buf = io.StringIO()
    r = ProgressReporter(enabled=False, color=False, stream=buf)
    r.banner("0.1.0", account_hint="readonly")
    r.phase("Collecting components")
    r.update(3, 10, "EC2InstanceCollector · us-east-1")
    r.finish_phase("done")
    assert buf.getvalue() == ""


def test_for_cli_disabled_when_not_a_tty() -> None:
    # A StringIO is not a TTY, so the live UI must stay off regardless of flags.
    buf = io.StringIO()
    r = ProgressReporter.for_cli(quiet=False, verbose=False, no_progress=False, stream=buf)
    assert r.enabled is False
    assert r.color is False


def test_summary_box_lines_are_equal_width() -> None:
    r = ProgressReporter(enabled=True, color=False, stream=io.StringIO())
    box = r.summary_box(
        [("Components", "412"), ("Regions", "3 (us-east-1, us-west-2)"), ("Errors", "0")],
        title="PCI DSS 4.0.1 inventory complete",
    )
    widths = {len(ln) for ln in box.splitlines()}
    assert len(widths) == 1, f"summary box not flush: widths={widths}"


def test_banner_lines_are_equal_width() -> None:
    buf = io.StringIO()
    r = ProgressReporter(enabled=True, color=False, stream=buf)
    r.banner("0.1.0")
    widths = {len(ln) for ln in _plain_lines(buf.getvalue())}
    assert len(widths) == 1, f"banner not flush: widths={widths}"


def test_summary_box_has_no_ansi_when_color_off() -> None:
    r = ProgressReporter(enabled=True, color=False, stream=io.StringIO())
    box = r.summary_box([("Components", "1")], title="t")
    assert "\033[" not in box


def test_run_work_units_invokes_callback_and_survives_callback_errors() -> None:
    units = [
        WorkUnit(account_id="111", region="us-east-1", service="ec2", label="L1", fn=lambda: [1, 2]),
        WorkUnit(account_id="111", region="us-east-1", service="s3", label="L2", fn=lambda: []),
    ]
    seen: list[tuple[int, int, int]] = []

    def cb(done: int, total: int, unit: WorkUnit, n_records: int) -> None:
        seen.append((done, total, n_records))
        raise RuntimeError("callback blew up — must not abort the run")

    records = run_work_units(units, max_workers=2, on_unit_done=cb)
    # Both records still collected despite the callback raising every time.
    assert sorted(records) == [1, 2]
    # Callback fired once per unit with the correct running total.
    assert len(seen) == 2
    assert {s[1] for s in seen} == {2}
    assert {s[0] for s in seen} == {1, 2}


def test_run_work_units_start_end_callbacks_survive_errors() -> None:
    units = [
        WorkUnit("111", "us-east-1", "ec2", "L1", fn=lambda: [1]),
        WorkUnit("111", "us-east-1", "s3", "L2", fn=lambda: [2, 3]),
    ]
    starts: list[str] = []
    ends: list[str] = []

    def on_start(u: WorkUnit) -> None:
        starts.append(u.label)
        raise RuntimeError("start cb blew up")

    def on_end(u: WorkUnit) -> None:
        ends.append(u.label)
        raise RuntimeError("end cb blew up")

    records = run_work_units(units, max_workers=2, on_unit_start=on_start, on_unit_end=on_end)
    assert sorted(records) == [1, 2, 3]
    assert sorted(starts) == ["L1", "L2"]
    assert sorted(ends) == ["L1", "L2"]


def test_error_collector_count_and_recent_order() -> None:
    ec = ErrorCollector()
    for i in range(5):
        ec.record(CollectionError("111", "us-east-1", f"svc{i}", "Op", "AccessDenied", "m"))
    assert ec.count == 5
    recent = ec.recent(3)
    # recent() preserves capture order (not the sorted .errors view).
    assert [e.service for e in recent] == ["svc2", "svc3", "svc4"]
    assert ec.recent(0) == []


def test_activity_tracker_records_and_idle_state() -> None:
    t = ActivityTracker()
    t.begin("EC2InstanceCollector", "us-east-1")
    snap = t.snapshot()
    assert snap[0].active is True
    assert snap[0].label == "EC2InstanceCollector"
    t.end()
    t.add_records(7)
    snap = t.snapshot()
    assert snap[0].active is False
    assert snap[0].completed == 1
    assert t.total_records == 7


def test_worker_dashboard_disabled_is_noop_and_restores_logging() -> None:
    # A disabled reporter must not touch stderr or the logging configuration.
    buf = io.StringIO()
    sentinel = logging.StreamHandler(io.StringIO())
    root = logging.getLogger()
    saved = root.handlers[:]
    root.handlers = [sentinel]
    try:
        r = ProgressReporter(enabled=False, color=False, stream=buf)
        tracker = ActivityTracker()
        ec = ErrorCollector()
        units = [WorkUnit("111", "us-east-1", "ec2", "L1", fn=lambda: [1, 2])]
        with r.worker_dashboard(tracker, ec, total=len(units)) as dash:
            records = run_work_units(
                units, 2,
                on_unit_start=dash.on_start,
                on_unit_end=dash.on_end,
                on_unit_done=dash.on_done,
            )
            dash.set_summary("done")
        assert sorted(records) == [1, 2]
        assert buf.getvalue() == ""  # no live output when disabled
        assert root.handlers == [sentinel]  # logging untouched
        assert tracker.total_records == 2  # counting still works
    finally:
        root.handlers = saved


def test_worker_dashboard_record_noun_omitted_for_stage23() -> None:
    # Stage 2/3 phases hide the record segment (record_noun="") because their
    # units merge results out-of-band rather than returning records.
    r = ProgressReporter(enabled=False, color=False, stream=io.StringIO())
    tracker = ActivityTracker()
    ec = ErrorCollector()
    units = [WorkUnit("111", "us-east-1", "ec2", "gap-fetch", fn=lambda: [])]
    with r.worker_dashboard(
        tracker, ec, total=len(units),
        title="Gap-fetch: NACLs + route tables",
        unit_noun="account-regions", record_noun="",
    ) as dash:
        records = run_work_units(
            units, 2,
            on_unit_start=dash.on_start, on_unit_end=dash.on_end, on_unit_done=dash.on_done,
        )
        dash.set_summary("live NACL/route data")
    assert records == []  # units merge out-of-band; no records returned
    assert tracker.snapshot()[0].completed == 1


def test_clip_visible_preserves_ansi_and_caps_width() -> None:
    line = _Ansi.GREEN + "X" * 50 + _Ansi.RESET + _Ansi.CYAN + "Y" * 50 + _Ansi.RESET
    out = _clip_visible(line, 10)
    assert _visible_len(out) == 10  # capped to visible columns
    assert out.endswith(_Ansi.RESET)  # colour reset appended — no leak
    # No severed escape sequence (every ESC[ is closed by an 'm').
    assert not re.search(r"\x1b\[[0-9;]*$", out)


def _force_terminal_size(monkeypatch, cols: int, rows: int) -> None:
    monkeypatch.setattr(
        progress_mod.shutil, "get_terminal_size",
        lambda *a: os.terminal_size((cols, rows)),
    )


def test_dashboard_frame_bounded_to_terminal_height(monkeypatch) -> None:
    # Regression: a frame taller than the viewport caused the terminal to scroll,
    # breaking the cursor-up rewind so each repaint stacked a new frame (runaway
    # green block / duplicated bars). The frame must clamp to rows-1.
    _force_terminal_size(monkeypatch, 120, 10)
    buf = io.StringIO()
    r = ProgressReporter(enabled=True, color=True, stream=buf)
    tr = ActivityTracker()
    ec = ErrorCollector()
    for _ in range(12):
        tr.begin("ApiGatewayRestCollector", "ap-southeast-4")
    for _ in range(50):
        ec.record(CollectionError("acct", "ca-central-1", "ecr", "GetRepositoryPolicy",
                                  "RepositoryPolicyNotFoundException", "none"))

    dash = _Dashboard(r, tr, ec, total=813)
    prev_height = 0
    for n in range(3):
        before = buf.tell()
        dash._paint()
        chunk = buf.getvalue()[before:]
        emitted = chunk.count("\n")
        m = re.match(r"\x1b\[(\d+)A", chunk)
        rewind = int(m.group(1)) if m else 0
        assert emitted <= 9, f"frame exceeded rows-1: {emitted}"
        if n > 0:
            assert rewind == prev_height, "rewind != previous frame height — frames would stack"
        prev_height = emitted
