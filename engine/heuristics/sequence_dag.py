"""
engine/heuristics/sequence_dag.py – Behavioural syscall sequence detector.

Tracks a per-PID, per-filepath finite state machine (FSM) to recognise
two classic ransomware patterns:

  **Pattern A — In-Place Encryption:**
    EVENT_OPEN → EVENT_WRITE (high entropy) → EVENT_RENAME (extension change)

  **Pattern B — Copy-and-Shred:**
    EVENT_OPEN(A) → EVENT_WRITE(B, high entropy) → EVENT_UNLINK(A)

Each completed destructive cycle within a sliding 2-second window
increments a cycle counter *C* per PID.  Scoring is exponential:

    ΔS = 10 × 1.5^C

This tolerates single-file operations (e.g. saving a compressed doc)
while exponentially penalising automated encryption loops.
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING

from engine.config import (
    DAG_BASE_SCORE,
    DAG_EXPONENT_BASE,
    DAG_WINDOW_SEC,
    ENTROPY_INLINE_HIGH,
    EVENT_OPEN,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_WRITE,
)

if TYPE_CHECKING:
    from engine.state_tracker import PIDState

logger = logging.getLogger(__name__)


def _prune_stale(state: "PIDState", now: float) -> None:
    """Remove DAG entries older than the sliding window."""
    cutoff = now - DAG_WINDOW_SEC
    stale = [
        fp for fp, (_, ts) in state.dag_state.items()
        if ts < cutoff
    ]
    for fp in stale:
        del state.dag_state[fp]


def _score_cycle(state: "PIDState", label: str) -> float:
    """Increment cycle counter and return the exponential score delta."""
    state.dag_cycles += 1
    delta = DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** state.dag_cycles)
    logger.debug(
        "DAG cycle #%d  pid=%d  pattern=%s  ΔS=%.1f",
        state.dag_cycles, state.pid, label, delta,
    )
    state.triggered_heuristics.append(
        f"DESTRUCTIVE_SEQUENCE_DAG ({label}, cycle #{state.dag_cycles})"
    )
    return delta


def check_sequence(
    event: dict,
    state: "PIDState",
    now: float | None = None,
) -> float:
    """
    Advance the per-filepath FSM for *state.pid* and return a score delta.

    This function reads ``state.last_write_entropy`` (set by
    ``entropy.check_inline_entropy``) to determine whether a WRITE was
    high-entropy.  It must be called **after** the entropy check.

    Parameters
    ----------
    event : dict
        Canonical event dict.
    state : PIDState
        The PID's mutable state (``dag_state`` and ``dag_cycles`` are
        modified in-place).
    now : float | None
        Current monotonic time; defaults to ``time.monotonic()``.

    Returns
    -------
    float
        Score delta (0.0 if no cycle completed; exponential otherwise).
    """
    if now is None:
        now = time.monotonic()

    event_type = event.get("event_type")
    filename = event.get("filename", "")

    # Prune entries older than the 2-second DAG window
    _prune_stale(state, now)

    # ── OPEN: begin tracking the file ────────────────────────────────────
    if event_type == EVENT_OPEN and filename:
        state.dag_state[filename] = ("OPENED", now)
        return 0.0

    # ── WRITE: advance to WRITTEN_HIGH or WRITTEN_LOW ────────────────────
    if event_type == EVENT_WRITE and filename:
        h = state.last_write_entropy
        if h > ENTROPY_INLINE_HIGH:
            state.dag_state[filename] = ("WRITTEN_HIGH", now)
        else:
            state.dag_state[filename] = ("WRITTEN_LOW", now)
        return 0.0

    # ── RENAME: check for in-place encryption pattern (A) ────────────────
    if event_type == EVENT_RENAME:
        new_filename = event.get("new_filename", "")
        if not filename or not new_filename:
            return 0.0

        entry = state.dag_state.get(filename)
        if entry is not None and entry[0] == "WRITTEN_HIGH":
            # Check for extension change
            _, old_ext = os.path.splitext(filename)
            _, new_ext = os.path.splitext(new_filename)
            if old_ext != new_ext:
                # In-place encryption cycle complete
                state.dag_state.pop(filename, None)
                return _score_cycle(
                    state,
                    f"OPEN→WRITE→RENAME {old_ext}→{new_ext}",
                )
        return 0.0

    # ── UNLINK: check for copy-and-shred pattern (B) ─────────────────────
    if event_type == EVENT_UNLINK and filename:
        entry = state.dag_state.get(filename)
        if entry is not None and entry[0] == "OPENED":
            # Was this file only opened (not written)?  Check if the PID
            # has written high-entropy data to *another* file recently.
            has_high_write_elsewhere = any(
                fsm == "WRITTEN_HIGH"
                for fp, (fsm, ts) in state.dag_state.items()
                if fp != filename and (now - ts) < DAG_WINDOW_SEC
            )
            if has_high_write_elsewhere:
                state.dag_state.pop(filename, None)
                return _score_cycle(state, "OPEN→WRITE(other)→UNLINK")
        return 0.0

    return 0.0
