"""
engine/tests/test_state_tracker.py – Unit tests for StateTracker & PIDState.

Covers:
  • PIDState creation and field defaults
  • Exponential score decay  S(t) = S(t₀)·e^{-λ(t-t₀)}
  • Sliding-window velocity tracking
  • Extension-uniformity burst detection (+50)
  • Stale-PID cleanup
"""

from __future__ import annotations

import math
import time

import pytest

from engine.config import (
    EXT_MUTATION_MIN_COUNT,
    EVENT_RENAME,
    SCORE_DECAY_LAMBDA,
    SCORE_EXTENSION_UNIFORM,
)
from engine.state_tracker import PIDState, StateTracker


class TestPIDState:
    def test_defaults(self) -> None:
        s = PIDState(pid=42, comm="test", uid=1000)
        assert s.pid == 42
        assert s.comm == "test"
        assert s.uid == 1000
        assert s.risk_score == 0.0
        assert len(s.fd_map) == 0
        assert len(s.magic_bytes) == 0
        assert len(s.events_window) == 0
        assert s.dag_cycles == 0
        assert s.last_write_entropy == 0.0


class TestScoreDecay:
    def test_decay_reduces_score(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        t0 = time.monotonic()
        state.risk_score = 50.0
        state.last_score_time = t0

        # Simulate 2 seconds passing
        t1 = t0 + 2.0
        tracker.apply_decay(state, now=t1)
        expected = 50.0 * math.exp(-SCORE_DECAY_LAMBDA * 2.0)
        assert abs(state.risk_score - expected) < 0.001

    def test_decay_no_time_elapsed(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        t0 = time.monotonic()
        state.risk_score = 50.0
        state.last_score_time = t0
        tracker.apply_decay(state, now=t0)
        assert state.risk_score == 50.0

    def test_add_score_applies_decay_first(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        t0 = time.monotonic()
        state.risk_score = 40.0
        state.last_score_time = t0

        t1 = t0 + 1.0
        tracker.add_score(state, 20.0, now=t1)
        decayed = 40.0 * math.exp(-SCORE_DECAY_LAMBDA * 1.0)
        assert abs(state.risk_score - (decayed + 20.0)) < 0.001

    def test_decay_approaches_zero(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1)
        state.risk_score = 100.0
        state.last_score_time = time.monotonic()
        tracker.apply_decay(state, now=state.last_score_time + 20.0)
        assert state.risk_score < 0.01


class TestVelocity:
    def test_event_velocity(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        base = time.monotonic()

        # Inject 10 events at known timestamps within the window
        for i in range(10):
            state.events_window.append(base + i * 0.05)
        state.last_event_time = base + 0.45

        vel = tracker.get_event_velocity(state)
        # All 10 events should be within the 1-sec window
        assert vel >= 9.0  # allow for minor pruning at boundary

    def test_old_events_pruned(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        old = time.monotonic() - 5.0  # 5 seconds ago
        for i in range(20):
            state.events_window.append(old + i * 0.01)

        vel = tracker.get_event_velocity(state)
        assert vel == 0.0  # all events are stale


class TestExtensionUniformity:
    def _make_rename_event(self, filename: str, new_filename: str) -> dict:
        return {
            "event_type": EVENT_RENAME,
            "filename": filename,
            "new_filename": new_filename,
        }

    def test_burst_triggers_at_threshold(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        now = time.monotonic()

        # Rename 5 distinct files to .locked  (exactly at threshold)
        total = 0.0
        for i in range(EXT_MUTATION_MIN_COUNT):
            evt = self._make_rename_event(
                f"/home/user/file_{i}.txt",
                f"/home/user/file_{i}.txt.locked",
            )
            total += tracker.check_extension_uniformity(state, evt, now=now + i * 0.1)

        assert total == SCORE_EXTENSION_UNIFORM

    def test_below_threshold_no_trigger(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        now = time.monotonic()

        total = 0.0
        for i in range(EXT_MUTATION_MIN_COUNT - 1):
            evt = self._make_rename_event(
                f"/home/user/file_{i}.txt",
                f"/home/user/file_{i}.txt.locked",
            )
            total += tracker.check_extension_uniformity(state, evt, now=now)

        assert total == 0.0

    def test_mixed_extensions_no_trigger(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        now = time.monotonic()

        exts = [".enc", ".locked", ".crypt", ".odin", ".evil"]
        total = 0.0
        for i, ext in enumerate(exts):
            evt = self._make_rename_event(
                f"/home/user/file_{i}.txt",
                f"/home/user/file_{i}{ext}",
            )
            total += tracker.check_extension_uniformity(state, evt, now=now)

        # Each ext appears only once → no burst
        assert total == 0.0

    def test_non_rename_ignored(self) -> None:
        tracker = StateTracker()
        state = tracker.get_or_create(1, "proc")
        evt = {"event_type": 2, "filename": "/a.txt", "new_filename": "/a.locked"}
        assert tracker.check_extension_uniformity(state, evt) == 0.0


class TestCleanup:
    def test_stale_pids_removed(self) -> None:
        tracker = StateTracker()
        s1 = tracker.get_or_create(1, "old")
        s1.last_event_time = time.monotonic() - 60.0  # 60s stale
        s2 = tracker.get_or_create(2, "fresh")
        s2.last_event_time = time.monotonic()

        tracker.cleanup_stale(max_age_sec=30.0)
        assert 1 not in tracker.active_pids
        assert 2 in tracker.active_pids

    def test_remove_specific_pid(self) -> None:
        tracker = StateTracker()
        tracker.get_or_create(42, "target")
        assert 42 in tracker.active_pids
        tracker.remove(42)
        assert 42 not in tracker.active_pids
