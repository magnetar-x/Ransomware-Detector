"""
engine/state_tracker.py – Per-PID stateful tracking with sliding windows
and exponential score decay.

Maintains one ``PIDState`` object per tracked process, holding:
  • Cumulative risk score with time-based exponential decay
  • File-descriptor → filepath mapping (populated on OPEN, cleared on CLOSE)
  • Magic-byte cache for known-format detection
  • Sliding-window ``deque`` for I/O velocity measurement
  • Rename-extension history for uniformity-burst detection
  • Per-filepath DAG FSM state (used by ``sequence_dag.py``)
  • Recent target files list (capped, for ALERT packets)
"""

from __future__ import annotations

import math
import os
import time
from collections import deque
from typing import Any

from engine.config import (
    EXT_MUTATION_MIN_COUNT,
    EXT_MUTATION_WINDOW_SEC,
    EVENT_RENAME,
    EVENT_CLOSE,
    EVENT_OPEN,
    EVENT_WRITE,
    KNOWN_RENAME_EXTENSIONS,
    SCORE_DECAY_LAMBDA,
    SCORE_EXTENSION_UNIFORM,
    SLIDING_WINDOW_SEC,
)

# Maximum target-files kept per PID (for ALERT packet sample)
_MAX_TARGET_FILES = 10


# ---------------------------------------------------------------------------
# PIDState – per-process state container
# ---------------------------------------------------------------------------

class PIDState:
    """Mutable per-PID state bucket.

    All mutable fields live here; ``StateTracker`` provides the methods
    that manipulate them.
    """

    __slots__ = (
        "pid",
        "comm",
        "uid",
        # ── scoring ──
        "risk_score",
        "last_score_time",
        # ── fd / magic tracking ──
        "fd_map",
        "magic_bytes",
        # ── velocity window ──
        "events_window",
        "write_events_window",
        "rename_events_window",
        # ── extension uniformity ──
        "rename_extensions",
        # ── sequence-DAG state ──
        "dag_cycles",
        "dag_state",
        # ── telemetry helpers ──
        "target_files",
        "triggered_heuristics",
        # ── entropy bridge ──
        "last_write_entropy",
        # ── housekeeping ──
        "last_event_time",
    )

    def __init__(self, pid: int, comm: str = "", uid: int = 0) -> None:
        self.pid: int = pid
        self.comm: str = comm
        self.uid: int = uid

        self.risk_score: float = 0.0
        self.last_score_time: float = time.monotonic()

        # fd → filepath  (populated on EVENT_OPEN, removed on EVENT_CLOSE)
        self.fd_map: dict[int, str] = {}
        # filepath → first-4-bytes of known file (for magic-overwrite detection)
        self.magic_bytes: dict[str, bytes] = {}

        # Timestamps of recent events for velocity measurement
        self.events_window: deque[float] = deque()
        self.write_events_window: deque[float] = deque()
        self.rename_events_window: deque[float] = deque()

        # (timestamp, new_extension, original_filename)  for rename-uniformity
        self.rename_extensions: deque[tuple[float, str, str]] = deque()

        # Sequence-DAG tracking
        self.dag_cycles: int = 0
        # filepath → (fsm_state, timestamp)
        #   fsm_state ∈ {"OPENED", "WRITTEN_HIGH", "WRITTEN_LOW"}
        self.dag_state: dict[str, tuple[str, float]] = {}

        # Last N affected file paths (for ALERT telemetry)
        self.target_files: list[str] = []
        # Human-readable heuristic labels that fired
        self.triggered_heuristics: list[str] = []

        # Set by entropy.check_inline_entropy on every EVENT_WRITE
        self.last_write_entropy: float = 0.0

        self.last_event_time: float = time.monotonic()


# ---------------------------------------------------------------------------
# StateTracker – manages the PID → PIDState map
# ---------------------------------------------------------------------------

class StateTracker:
    """
    Central state manager for the detection engine.

    Provides O(1) per-PID lookup, exponential score decay, I/O velocity
    measurement, and extension-uniformity burst detection.
    """

    def __init__(self) -> None:
        self._states: dict[int, PIDState] = {}

    # -- PID lifecycle ------------------------------------------------------

    def get_or_create(
        self, pid: int, comm: str = "", uid: int = 0,
    ) -> PIDState:
        """Return the ``PIDState`` for *pid*, creating one if needed."""
        state = self._states.get(pid)
        if state is None:
            state = PIDState(pid, comm, uid)
            self._states[pid] = state
        else:
            # Keep comm/uid up-to-date (may change across exec)
            if comm:
                state.comm = comm
            if uid:
                state.uid = uid
        return state

    def remove(self, pid: int) -> None:
        """Remove a PID from tracking (e.g. after SIGKILL)."""
        self._states.pop(pid, None)

    def cleanup_stale(self, max_age_sec: float = 30.0) -> None:
        """Evict PIDs that have had no events for *max_age_sec*."""
        now = time.monotonic()
        stale = [
            pid for pid, s in self._states.items()
            if now - s.last_event_time > max_age_sec
        ]
        for pid in stale:
            del self._states[pid]

    # -- scoring ------------------------------------------------------------

    def apply_decay(self, state: PIDState, now: float | None = None) -> None:
        r"""
        Apply exponential time-decay to the risk score:

            S(t) = S(t₀) · e^{-λ·(t − t₀)}

        Must be called **before** adding new score deltas.
        """
        if now is None:
            now = time.monotonic()
        dt = now - state.last_score_time
        if dt > 0.0:
            state.risk_score *= math.exp(-SCORE_DECAY_LAMBDA * dt)
            state.last_score_time = now

    def add_score(
        self,
        state: PIDState,
        delta: float,
        now: float | None = None,
    ) -> None:
        """Apply decay then add *delta* to the score."""
        if now is None:
            now = time.monotonic()
        self.apply_decay(state, now)
        state.risk_score += delta

    # -- velocity -----------------------------------------------------------

    def record_event(self, state: PIDState, event: dict) -> None:
        """Record an event timestamp into the sliding window and update the
        target-files list."""
        now = time.monotonic()
        state.events_window.append(now)
        event_type = event.get("event_type")
        if event_type == EVENT_OPEN:
            fd = event.get("fd", -1)
            filename = event.get("filename", "")
            if fd is not None and fd >= 0 and filename:
                state.fd_map[int(fd)] = filename
        elif event_type == EVENT_CLOSE:
            fd = event.get("fd", -1)
            if fd is not None and fd >= 0:
                state.fd_map.pop(int(fd), None)
        elif event_type == EVENT_WRITE:
            state.write_events_window.append(now)
        elif event_type == EVENT_RENAME:
            state.rename_events_window.append(now)
        state.last_event_time = now

        # Prune entries outside the 1-second window
        cutoff = now - SLIDING_WINDOW_SEC
        while state.events_window and state.events_window[0] < cutoff:
            state.events_window.popleft()
        for window in (state.write_events_window, state.rename_events_window):
            while window and window[0] < cutoff:
                window.popleft()

        # Track affected filenames for ALERT packets
        fname = event.get("filename", "")
        if fname and (not state.target_files or state.target_files[-1] != fname):
            state.target_files.append(fname)
            if len(state.target_files) > _MAX_TARGET_FILES:
                state.target_files = state.target_files[-_MAX_TARGET_FILES:]

    def get_event_velocity(self, state: PIDState) -> float:
        """Return events-per-second over the current sliding window."""
        now = time.monotonic()
        cutoff = now - SLIDING_WINDOW_SEC
        while state.events_window and state.events_window[0] < cutoff:
            state.events_window.popleft()
        return len(state.events_window) / SLIDING_WINDOW_SEC

    def get_io_velocity(self, state: PIDState) -> dict[str, float]:
        """Return separate write and rename rates over the one-second window."""
        now = time.monotonic()
        cutoff = now - SLIDING_WINDOW_SEC
        for window in (state.write_events_window, state.rename_events_window):
            while window and window[0] < cutoff:
                window.popleft()
        return {
            "writes_per_sec": len(state.write_events_window) / SLIDING_WINDOW_SEC,
            "renames_per_sec": len(state.rename_events_window) / SLIDING_WINDOW_SEC,
        }

    # -- extension-uniformity burst detection --------------------------------

    def check_extension_uniformity(
        self,
        state: PIDState,
        event: dict,
        now: float | None = None,
    ) -> float:
        """
        On EVENT_RENAME: check whether >5 distinct files have been renamed
        to share the same new extension within a 3-second window.

        Returns the score delta (0.0 or +50.0).
        """
        if event.get("event_type") != EVENT_RENAME:
            return 0.0

        if now is None:
            now = time.monotonic()

        new_filename: str = event.get("new_filename", "")
        old_filename: str = event.get("filename", "")
        if not new_filename:
            return 0.0

        # Extract the new extension
        _, new_ext = os.path.splitext(new_filename)
        if not new_ext:
            return 0.0

        state.rename_extensions.append((now, new_ext, old_filename))

        # Prune entries outside the window
        cutoff = now - EXT_MUTATION_WINDOW_SEC
        while state.rename_extensions and state.rename_extensions[0][0] < cutoff:
            state.rename_extensions.popleft()

        # Count distinct original files per new extension
        ext_files: dict[str, set[str]] = {}
        for _ts, ext, orig_fname in state.rename_extensions:
            ext_files.setdefault(ext, set()).add(orig_fname)

        for ext, files in ext_files.items():
            if ext.lower() not in KNOWN_RENAME_EXTENSIONS and len(files) >= EXT_MUTATION_MIN_COUNT:
                # Fire once per burst — clear the history
                state.rename_extensions.clear()
                return SCORE_EXTENSION_UNIFORM

        return 0.0

    # -- accessors ----------------------------------------------------------

    @property
    def active_pids(self) -> dict[int, PIDState]:
        """Return the raw PID → PIDState mapping."""
        return self._states

    @property
    def active_pid_count(self) -> int:
        return len(self._states)
