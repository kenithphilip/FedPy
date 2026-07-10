"""Interactive terminal progress UI for long-running collection phases.

Dependency-light (stdlib only): a small :class:`ProgressReporter` that draws a
startup banner, live progress for the otherwise-silent phases of a run (region
probing, component collection, output writing), and a final summary box.

For component collection — the long, parallel phase — it renders a **live
multi-worker dashboard** (:class:`_Dashboard`): an overall progress bar, one row
per worker thread showing what each is collecting *right now*, and a streaming
"recent issues" pane fed from the run's :class:`ErrorCollector` so access gaps
and field-shape quirks are visible the instant they are captured, not at the end.

Design constraints:
- **Never interferes with machine use or logs.** Live output goes to *stderr* and
  only when stderr is an interactive TTY. When output is piped/redirected, or
  ``--quiet``/``--no-progress``/``--verbose`` is set, the whole UI is a no-op —
  the existing INFO logs carry the story.
- **The dashboard is the sole stderr writer while active.** A background thread
  repaints a fixed multi-line frame using cursor moves; a stray log line would
  corrupt that frame, so for the dashboard's lifetime the package's log handlers
  are swapped for one that captures WARNING+ records (flushed to stderr *after*
  the dashboard closes) — nothing is lost, and the frame stays clean.
- **Honors ``NO_COLOR``.** ANSI colour is used only on a colour-capable TTY.
- **The UI can never abort a run.** Every callback/repaint swallows its own errors.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from typing import TextIO

# Braille spinner frames — smooth and compact.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Block characters for the bar fill.
_FILL = "█"
_HALF = "▌"
_EMPTY = "░"

# Circled numbers used to label worker slots in the dashboard.
_SLOT_GLYPHS = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
_MAX_WORKER_ROWS = 16  # cap dashboard height for large pools
_ISSUE_ROWS = 4  # rows reserved for the streaming "recent issues" pane

# Error codes the tool treats as expected/benign (access gaps, opt-in regions,
# deprecated services) — shown amber in the issues pane; anything else is red.
# Kept in sync with concurrency.BENIGN_UNAVAILABLE_CODES.
_BENIGN_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "AuthorizationError", "OptInRequired", "SubscriptionRequiredException",
    "InvalidClientTokenId", "UnrecognizedClientException", "InvalidAction",
    "UnknownServiceError",
})


class _Ansi:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BLUE = "\033[34m"


def _fmt_elapsed(seconds: float) -> str:
    """Render elapsed seconds as ``M:SS`` (or ``H:MM:SS`` past an hour)."""
    secs = int(seconds)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


def _visible_len(text: str) -> int:
    """Length of ``text`` ignoring ANSI SGR escape sequences."""
    out = 0
    i = 0
    while i < len(text):
        if text[i] == "\033":
            j = text.find("m", i)
            if j != -1:
                i = j + 1
                continue
        out += 1
        i += 1
    return out


def _clip_visible(text: str, width: int) -> str:
    """Clip ``text`` to ``width`` *visible* columns without severing ANSI codes.

    ANSI SGR escapes are copied through verbatim (they cost zero columns) and a
    reset is appended if any escape was emitted, so a clipped coloured line can
    never leak its colour onto the rest of the terminal.
    """
    out: list[str] = []
    shown = 0
    saw_escape = False
    i = 0
    while i < len(text) and shown < width:
        if text[i] == "\033":
            j = text.find("m", i)
            if j != -1:
                out.append(text[i : j + 1])
                saw_escape = True
                i = j + 1
                continue
        out.append(text[i])
        shown += 1
        i += 1
    if saw_escape:
        out.append(_Ansi.RESET)
    return "".join(out)


def _truncate(text: str, width: int) -> str:
    """Truncate a plain (no-ANSI) string to ``width`` with an ellipsis."""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[: width - 1] + "…" if width > 1 else "…"


# --------------------------------------------------------------------------- #
# Live worker-activity tracking (thread-safe; written from worker threads).
# --------------------------------------------------------------------------- #
@dataclass
class _Slot:
    """What one worker thread is currently doing."""

    label: str = ""       # collector label, e.g. "EC2InstanceCollector"
    region: str = ""
    started: float = 0.0  # monotonic start of the current unit
    active: bool = False
    completed: int = 0    # units this slot has finished
    records: int = 0      # records this slot has produced


class ActivityTracker:
    """Thread-safe registry mapping each worker thread to its current activity.

    Worker threads call :meth:`begin`/:meth:`end` around each unit; the dashboard
    thread calls :meth:`snapshot` to read a consistent view. Threads are assigned
    stable, compact slot indices in first-seen order so the dashboard rows are
    stable.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._slots: dict[int, _Slot] = {}
        self._order: list[int] = []  # thread ids in first-seen order
        self.total_records = 0

    def _slot_for(self, tid: int) -> _Slot:
        slot = self._slots.get(tid)
        if slot is None:
            slot = _Slot()
            self._slots[tid] = slot
            self._order.append(tid)
        return slot

    def begin(self, label: str, region: str) -> None:
        tid = threading.get_ident()
        with self._lock:
            slot = self._slot_for(tid)
            slot.label = label
            slot.region = region
            slot.started = time.monotonic()
            slot.active = True

    def end(self) -> None:
        """Mark the calling worker's slot idle and bump its completed count."""
        tid = threading.get_ident()
        with self._lock:
            slot = self._slot_for(tid)
            slot.active = False
            slot.completed += 1

    def add_records(self, n: int) -> None:
        """Add ``n`` to the run-wide record total (called from the main thread)."""
        if not n:
            return
        with self._lock:
            self.total_records += n

    def snapshot(self) -> list[_Slot]:
        """Return a stable-ordered copy of all known worker slots."""
        with self._lock:
            return [
                _Slot(s.label, s.region, s.started, s.active, s.completed, s.records)
                for s in (self._slots[t] for t in self._order)
            ]


class _CapturingHandler(logging.Handler):
    """Buffers log records (instead of writing them) while the dashboard owns stderr.

    Records at or above ``passthrough_level`` are kept so they can be flushed to
    stderr *after* the dashboard closes — nothing is lost, and the live frame is
    never corrupted by an out-of-band log line. Lower-level records are dropped
    (they would only be INFO/DEBUG noise the dashboard already supersedes).
    """

    def __init__(self, formatter: logging.Formatter | None, passthrough_level: int) -> None:
        super().__init__()
        self._buffer: list[logging.LogRecord] = []
        self._passthrough_level = passthrough_level
        if formatter is not None:
            self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= self._passthrough_level:
            self._buffer.append(record)

    def drain(self) -> list[str]:
        fmt = self.formatter or logging.Formatter()
        return [fmt.format(r) for r in self._buffer]


class _Dashboard:
    """A background-thread, multi-line live dashboard for the collection phase.

    Owns stderr for its lifetime: on :meth:`start` it swaps the root log handlers
    for a capturing handler, then a daemon thread repaints a fixed-height frame
    (header bar + per-worker rows + recent-issues pane) a few times a second using
    ANSI cursor moves. :meth:`stop` halts the thread, restores logging, prints a
    final frame, and flushes any captured WARNING+ logs beneath it.
    """

    def __init__(self, reporter: "ProgressReporter", tracker: ActivityTracker,
                 errors: object, total: int, *, unit_noun: str = "units",
                 record_noun: str = "components", fps: float = 8.0) -> None:
        self._r = reporter
        self._tracker = tracker
        self._errors = errors  # duck-typed: .count, .recent(n)
        self._total = total
        self._unit_noun = unit_noun
        self._record_noun = record_noun
        self._interval = 1.0 / max(1.0, fps)
        self._done = 0
        self._start = time.monotonic()
        self._spin = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._frame_lines = 0  # height of the last painted frame (for cursor rewind)
        self._cap_handler: _CapturingHandler | None = None
        self._saved_handlers: list[logging.Handler] = []

    # -- log redirection ---------------------------------------------------- #
    def _install_capture(self) -> None:
        root = logging.getLogger()
        self._saved_handlers = root.handlers[:]
        fmt = self._saved_handlers[0].formatter if self._saved_handlers else None
        self._cap_handler = _CapturingHandler(fmt, passthrough_level=logging.WARNING)
        root.handlers = [self._cap_handler]

    def _restore_logging(self) -> None:
        root = logging.getLogger()
        root.handlers = self._saved_handlers

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        self._install_capture()
        self._thread = threading.Thread(target=self._loop, name="pci-dash", daemon=True)
        self._thread.start()

    def mark_done(self, done: int, total: int | None = None) -> None:
        with self._lock:
            self._done = done
            if total is not None:
                # Trust the real unit count from run_work_units over the caller's
                # pre-estimate (which may overcount if some accounts lack sessions).
                self._total = total

    def stop(self, summary: str = "") -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._restore_logging()
        # Erase the live frame and replace it with a one-line phase summary.
        self._erase_frame()
        self._r.finish_phase(summary)
        # Flush any WARNING+ logs captured during the dashboard's life, beneath it.
        if self._cap_handler is not None:
            for line in self._cap_handler.drain():
                self._r._write(line + "\n")

    # -- rendering ---------------------------------------------------------- #
    def _erase_frame(self) -> None:
        if self._frame_lines and self._r.enabled:
            # Move cursor up to the frame top and clear to end of screen.
            self._r._write(f"\033[{self._frame_lines}A\033[J")
            self._frame_lines = 0

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._paint()
            except Exception:  # noqa: BLE001 - the UI must never abort a run
                pass
            self._stop.wait(self._interval)

    def _paint(self) -> None:
        if not self._r.enabled:
            return
        c = self._r._c
        cols = shutil.get_terminal_size((90, 24)).columns
        with self._lock:
            done = self._done
        self._spin = (self._spin + 1) % len(_SPINNER)

        lines: list[str] = []

        # --- header progress bar ---
        frac = 0.0 if self._total <= 0 else max(0.0, min(1.0, done / self._total))
        bar_w = max(12, min(40, cols - 40))
        filled = int(frac * bar_w)
        bar = c(_FILL * filled, _Ansi.GREEN) + c(_EMPTY * (bar_w - filled), _Ansi.DIM)
        spin = c(_SPINNER[self._spin], _Ansi.CYAN)
        elapsed = _fmt_elapsed(time.monotonic() - self._start)
        rec = self._tracker.total_records
        err_n = self._errors.count  # type: ignore[attr-defined]
        err_txt = c(f"{err_n} issue(s)", _Ansi.YELLOW if err_n else _Ansi.DIM)
        rec_seg = f"{c(str(rec), _Ansi.BOLD)} {self._record_noun}  ·  " if self._record_noun else ""
        header = (f"  {spin} [{bar}] {int(frac*100):3d}%  "
                  f"{c(f'{done}/{self._total}', _Ansi.BOLD)} {self._unit_noun}  ·  "
                  f"{rec_seg}{err_txt}  ·  {c(elapsed, _Ansi.DIM)}")
        lines.append(header)
        lines.append("")

        # --- per-worker rows ---
        slots = self._tracker.snapshot()
        lines.append(c("  workers", _Ansi.DIM))
        shown = slots[:_MAX_WORKER_ROWS]
        now = time.monotonic()
        for i, s in enumerate(shown):
            glyph = _SLOT_GLYPHS[i] if i < len(_SLOT_GLYPHS) else "•"
            if s.active:
                dur = _fmt_elapsed(now - s.started) if s.started else "0:00"
                task = _truncate(f"{s.label} · {s.region}", max(10, cols - 34))
                row = (f"   {c(glyph, _Ansi.CYAN)} {c('▸', _Ansi.GREEN)} {task}  "
                       f"{c(dur, _Ansi.DIM)}")
            else:
                row = (f"   {c(glyph, _Ansi.DIM)} {c('·', _Ansi.DIM)} "
                       f"{c('idle', _Ansi.DIM)}  {c(f'{s.completed} done', _Ansi.DIM)}")
            lines.append(row)
        if len(slots) > _MAX_WORKER_ROWS:
            lines.append(c(f"   … +{len(slots) - _MAX_WORKER_ROWS} more workers", _Ansi.DIM))

        # --- recent issues pane (streaming) ---
        lines.append("")
        title = c("  recent issues", _Ansi.YELLOW if err_n else _Ansi.DIM)
        lines.append(f"{title} {c(f'({err_n} total)', _Ansi.DIM)}")
        recent = self._errors.recent(_ISSUE_ROWS)  # type: ignore[attr-defined]
        if not recent:
            lines.append(c("   none yet — all clear", _Ansi.DIM))
        else:
            for e in recent:
                sev = _Ansi.RED if e.error_code not in _BENIGN_CODES else _Ansi.YELLOW
                loc = f"{e.service}/{e.region}"
                msg = _truncate(f"{e.error_code}  {loc}  {e.operation}", max(10, cols - 6))
                lines.append(f"   {c('•', sev)} {c(msg, _Ansi.DIM)}")

        self._render_frame(lines)

    def _render_frame(self, lines: list[str]) -> None:
        """Repaint a fixed-height frame in place using cursor-up + clear-line.

        The frame is clamped to the terminal viewport (``rows - 1``). This is
        critical: if the frame is taller than the screen the terminal scrolls,
        after which "cursor up N" no longer lands on the frame's top row and each
        repaint would stack a fresh frame (the runaway green block / duplicated
        bars). A trailing reserved row keeps the final ``\\n`` from scrolling the
        frame up by one. Lines are clipped to the width without severing ANSI
        escapes so colour can never leak past the clip.
        """
        size = shutil.get_terminal_size((90, 24))
        cols = max(1, size.columns)
        max_rows = max(1, size.lines - 1)
        if len(lines) > max_rows:
            # Keep the head (bar + workers); drop overflow with a marker so the
            # frame height is bounded and the in-place rewind stays correct.
            keep = max_rows - 1
            lines = lines[:keep] + [self._r._c(f"  … +{len(lines) - keep} more line(s)", _Ansi.DIM)]

        out: list[str] = []
        if self._frame_lines:
            out.append(f"\033[{self._frame_lines}A")  # cursor up to frame top
        for ln in lines:
            out.append("\r\033[K" + _clip_visible(ln, cols) + "\n")
        self._r._write("".join(out))
        self._frame_lines = len(lines)


class ProgressReporter:
    """Render a startup banner, live phase progress bars, and a summary box.

    Construct with :meth:`for_cli` so TTY/colour/enabled detection is centralized.
    All methods are safe no-ops when ``enabled`` is False, so callers never need
    to branch.
    """

    def __init__(self, *, enabled: bool, color: bool, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = enabled
        self.color = color
        self._phase_title = ""
        self._phase_start = 0.0
        self._spin = 0
        self._line_open = False  # a live (carriage-return) line is currently drawn

    @classmethod
    def for_cli(cls, *, quiet: bool, verbose: bool, no_progress: bool,
                stream: TextIO | None = None) -> "ProgressReporter":
        """Build a reporter configured from CLI flags + the environment.

        Live progress is enabled only on an interactive TTY and when the user has
        not asked for quiet/verbose output or explicitly disabled it. ``--verbose``
        suppresses the bar so detailed logs are not clobbered.
        """
        out = stream if stream is not None else sys.stderr
        is_tty = bool(getattr(out, "isatty", lambda: False)())
        enabled = is_tty and not quiet and not verbose and not no_progress
        color = enabled and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"
        return cls(enabled=enabled, color=color, stream=out)

    # -- styling helper ----------------------------------------------------- #
    def _c(self, text: str, *codes: str) -> str:
        if not self.color or not codes:
            return text
        return "".join(codes) + text + _Ansi.RESET

    def _write(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    def _clear_line(self) -> None:
        if self._line_open:
            self._write("\r\033[K")
            self._line_open = False

    # -- banner ------------------------------------------------------------- #
    def banner(self, version: str, account_hint: str = "") -> None:
        """Print the startup banner (always shown unless the reporter is quiet)."""
        if not self.enabled:
            return
        inner = 58  # interior width between the box borders

        def boxed(segments: list[tuple[str, tuple[str, ...]]]) -> str:
            """Render one box row: 1-space margins + colour segments, padded flush.

            ``segments`` is a list of ``(text, ansi_codes)``; padding is computed
            from the *visible* (uncoloured) length so the right border aligns
            regardless of ANSI escapes.
            """
            visible = sum(len(t) for t, _ in segments)
            pad = " " * max(0, inner - 2 - visible)
            body = "".join(self._c(t, *codes) for t, codes in segments)
            bar = self._c("│", _Ansi.CYAN)
            return f"  {bar} {body}{pad} {bar}"

        top = "  " + self._c("┌" + "─" * inner + "┐", _Ansi.CYAN)
        bot = "  " + self._c("└" + "─" * inner + "┘", _Ansi.CYAN)
        row1 = boxed([
            ("■  ", (_Ansi.CYAN, _Ansi.BOLD)),
            ("PCI DSS v4.0.1  ·  AWS Asset Inventory", (_Ansi.BOLD,)),
        ])
        row2 = boxed([
            ("read-only", (_Ansi.GREEN,)),
            (" inventory · scope · evidence", ()),
            (f"    v{version}", (_Ansi.DIM,)),
        ])
        lines = ["", top, row1, row2, bot]
        if account_hint:
            lines.append(f"  {self._c('account ' + account_hint, _Ansi.DIM)}")
        lines.append("")
        self._write("\n".join(lines) + "\n")

    # -- phases ------------------------------------------------------------- #
    def phase(self, title: str) -> None:
        """Announce a new phase and reset the bar/timer for it."""
        if not self.enabled:
            return
        self._clear_line()
        self._phase_title = title
        self._phase_start = time.monotonic()
        self._spin = 0
        arrow = self._c("▶", _Ansi.CYAN, _Ansi.BOLD)
        self._write(f"  {arrow} {self._c(title, _Ansi.BOLD)}\n")

    def update(self, current: int, total: int, detail: str = "") -> None:
        """Redraw the live progress bar for the current phase."""
        if not self.enabled:
            return
        cols = shutil.get_terminal_size((80, 24)).columns
        frac = 0.0 if total <= 0 else max(0.0, min(1.0, current / total))
        pct = int(frac * 100)

        # Bar width adapts to terminal, leaving room for the stats suffix.
        bar_w = max(10, min(34, cols - 38))
        filled = int(frac * bar_w)
        bar = _FILL * filled + _EMPTY * (bar_w - filled)
        bar = self._c(bar, _Ansi.GREEN)

        self._spin = (self._spin + 1) % len(_SPINNER)
        spin = self._c(_SPINNER[self._spin], _Ansi.CYAN)
        elapsed = self._c(_fmt_elapsed(time.monotonic() - self._phase_start), _Ansi.DIM)
        count = self._c(f"{current}/{total}", _Ansi.BOLD)
        pct_s = f"{pct:3d}%"

        line = f"  {spin} [{bar}] {pct_s}  {count}"
        if detail:
            # Truncate detail so the whole line fits the terminal width.
            budget = max(0, cols - 4 - bar_w - 24)
            shown = detail if len(detail) <= budget else detail[: max(0, budget - 1)] + "…"
            line += f"  {self._c(shown, _Ansi.DIM)}"
        line += f"  {elapsed}"

        self._clear_line()
        self._write("\r" + line)
        self._line_open = True

    def finish_phase(self, summary: str = "") -> None:
        """Close the live line for the current phase with a check + summary."""
        if not self.enabled:
            return
        self._clear_line()
        check = self._c("✓", _Ansi.GREEN, _Ansi.BOLD)
        elapsed = _fmt_elapsed(time.monotonic() - self._phase_start)
        tail = f"  {self._c(summary, _Ansi.DIM)}" if summary else ""
        self._write(f"  {check} {self._phase_title}{tail}  {self._c(elapsed, _Ansi.DIM)}\n")

    # -- live worker dashboard ---------------------------------------------- #
    def worker_dashboard(
        self, tracker: ActivityTracker, errors: object, total: int, *,
        title: str = "Collecting components", unit_noun: str = "units",
        record_noun: str = "components",
    ) -> "_DashboardHandle":
        """Begin the live multi-worker dashboard for a parallel AWS phase.

        Used by every stage's parallel phase (Stage 1 collection, Stage 2
        gap-fetch, Stage 3 follow-up findings). Returns a handle exposing
        ``on_start``/``on_end``/``on_done`` callbacks for :func:`run_work_units`
        plus :meth:`close`. When the reporter is disabled the handle is inert, so
        the caller wires it up unconditionally. Use as a context manager so the
        dashboard always stops and logging is always restored, even on error.

        ``record_noun`` empty → the components/records segment is hidden (Stage
        2/3 units merge their results out-of-band rather than returning records).
        """
        self._phase_title = title
        self._phase_start = time.monotonic()
        dash = (
            _Dashboard(self, tracker, errors, total,
                       unit_noun=unit_noun, record_noun=record_noun)
            if self.enabled else None
        )
        if dash is not None:
            dash.start()
        return _DashboardHandle(self, dash, tracker)

    # -- summary box -------------------------------------------------------- #
    def summary_box(self, lines: list[tuple[str, str]], title: str = "Run complete") -> str:
        """Return a boxed, aligned key/value summary (also usable when disabled).

        Returned as a string so the caller can print it to stdout (machine-facing
        stream) regardless of whether the live UI was enabled.
        """
        label_w = max((len(k) for k, _ in lines), default=0)
        body_w = max((label_w + 2 + len(v) for _, v in lines), default=0)
        inner = max(len(title), body_w) + 2
        use_color = self.color

        def c(text: str, *codes: str) -> str:
            if not use_color or not codes:
                return text
            return "".join(codes) + text + _Ansi.RESET

        top = c("╔" + "═" * inner + "╗", _Ansi.CYAN)
        sep = c("╟" + "─" * inner + "╢", _Ansi.CYAN)
        bot = c("╚" + "═" * inner + "╝", _Ansi.CYAN)
        side = c("║", _Ansi.CYAN)

        out = [top, f"{side} {c(title.ljust(inner - 1), _Ansi.BOLD)}{side}", sep]
        for k, v in lines:
            row = f"{k.ljust(label_w)}  {c(v, _Ansi.BOLD)}"
            # Pad accounting for invisible ANSI by padding the plain content first.
            plain = f"{k.ljust(label_w)}  {v}"
            pad = " " * max(0, inner - 1 - len(plain))
            out.append(f"{side} {row}{pad}{side}")
        out.append(bot)
        return "\n".join(out)


@dataclass
class _DashboardHandle:
    """Wires :func:`run_work_units` callbacks to a live dashboard (or no-ops).

    Doubles as a context manager so the dashboard is always stopped and logging
    always restored. ``on_start``/``on_end`` run inside worker threads (delegating
    to the thread-safe :class:`ActivityTracker`); ``on_done`` runs on the main
    thread and advances the overall counter.
    """

    reporter: "ProgressReporter"
    dashboard: "_Dashboard | None"
    tracker: ActivityTracker
    summary: str = ""

    def on_start(self, unit: object) -> None:
        self.tracker.begin(getattr(unit, "label", ""), getattr(unit, "region", ""))

    def on_end(self, unit: object) -> None:
        # Runs in the worker thread the instant the unit finishes — mark idle.
        self.tracker.end()

    def on_done(self, done: int, total: int, unit: object, n_records: int) -> None:
        # Main thread: attribute produced records to the run total, advance the
        # bar, and sync the authoritative unit total from run_work_units.
        self.tracker.add_records(n_records)
        if self.dashboard is not None:
            self.dashboard.mark_done(done, total)

    def set_summary(self, summary: str) -> None:
        self.summary = summary

    def close(self) -> None:
        if self.dashboard is not None:
            self.dashboard.stop(self.summary)
        else:
            # Disabled reporter: still emit a one-line phase completion if enabled
            # output was somehow on; otherwise a pure no-op.
            self.reporter.finish_phase(self.summary)

    def __enter__(self) -> "_DashboardHandle":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
