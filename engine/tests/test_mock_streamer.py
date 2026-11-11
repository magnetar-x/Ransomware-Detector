"""
engine/tests/test_mock_streamer.py – Unit tests for MockBPFStreamer.

Verifies:
  1. Every scenario produces events with the correct canonical dict shape.
  2. Event field values are sane (types, ranges, non-empty strings).
  3. High-entropy and low-entropy payloads are generated correctly per scenario.
  4. The streamer respects ``stop()`` and exits cleanly.
  5. Unknown scenarios raise ``ValueError``.
"""

from __future__ import annotations

import threading
import time

import pytest

from engine.mock_streamer import AVAILABLE_SCENARIOS, MockBPFStreamer

# -- Canonical event dict keys that EVERY event must contain ----------------
REQUIRED_KEYS = {
    "timestamp_ns", "pid", "tid", "uid", "event_type",
    "fd", "bytes_count", "comm", "filename", "new_filename",
    "payload_sample",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collect_events(scenario: str, count: int = 200, eps: int = 50_000,
                    canary_paths: list[str] | None = None) -> list[dict]:
    """Run a MockBPFStreamer and collect *count* events, then stop."""
    collected: list[dict] = []
    lock = threading.Lock()

    def _cb(evt: dict) -> None:
        with lock:
            collected.append(evt)
            if len(collected) >= count:
                streamer.stop()

    streamer = MockBPFStreamer(
        scenario=scenario, events_per_sec=eps,
        canary_paths=canary_paths,
    )
    streamer.register_callback(_cb)

    # Run in a thread so we can enforce a timeout
    t = threading.Thread(target=streamer.start, daemon=True)
    t.start()
    t.join(timeout=5.0)
    if t.is_alive():
        streamer.stop()
        t.join(timeout=2.0)

    return collected


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEventShape:
    """Every event from any scenario must match the canonical dict shape."""

    @pytest.mark.parametrize("scenario", AVAILABLE_SCENARIOS)
    def test_all_keys_present(self, scenario: str) -> None:
        events = _collect_events(scenario, count=50)
        assert len(events) >= 50, f"Only collected {len(events)} events"
        for evt in events:
            missing = REQUIRED_KEYS - set(evt.keys())
            assert not missing, f"Missing keys in {scenario}: {missing}"

    @pytest.mark.parametrize("scenario", AVAILABLE_SCENARIOS)
    def test_field_types(self, scenario: str) -> None:
        events = _collect_events(scenario, count=30)
        for evt in events:
            assert isinstance(evt["timestamp_ns"], int)
            assert isinstance(evt["pid"], int) and evt["pid"] > 0
            assert isinstance(evt["tid"], int)
            assert isinstance(evt["uid"], int)
            assert isinstance(evt["event_type"], int)
            assert evt["event_type"] in (1, 2, 3, 4, 5)
            assert isinstance(evt["fd"], int)
            assert isinstance(evt["bytes_count"], int) and evt["bytes_count"] >= 0
            assert isinstance(evt["comm"], str) and len(evt["comm"]) > 0
            assert isinstance(evt["filename"], str)
            assert isinstance(evt["new_filename"], str)
            assert isinstance(evt["payload_sample"], bytes)


class TestScenarioContent:
    """Verify scenario-specific semantics."""

    def test_benign_compiler_low_entropy_payload(self) -> None:
        events = _collect_events("benign_compiler", count=100)
        writes = [e for e in events if e["event_type"] == 2]
        assert len(writes) > 0, "Expected WRITE events from compiler scenario"
        for w in writes:
            if len(w["payload_sample"]) > 0:
                # Low-entropy payloads → all bytes in printable ASCII range
                assert all(0x20 <= b <= 0x7E for b in w["payload_sample"]), \
                    "Compiler payload should be low-entropy ASCII"

    def test_ransomware_inplace_high_entropy_payload(self) -> None:
        events = _collect_events("ransomware_inplace", count=100)
        writes = [e for e in events if e["event_type"] == 2]
        assert len(writes) > 0
        # At least some writes should have high-entropy payloads
        # (not all ASCII printable)
        non_ascii_count = sum(
            1 for w in writes
            if w["payload_sample"] and
            not all(0x20 <= b <= 0x7E for b in w["payload_sample"])
        )
        assert non_ascii_count > 0, "Expected high-entropy payloads in ransomware"

    def test_ransomware_inplace_has_renames(self) -> None:
        events = _collect_events("ransomware_inplace", count=100)
        renames = [e for e in events if e["event_type"] == 3]
        assert len(renames) > 0
        for r in renames:
            assert ".locked" in r["new_filename"]

    def test_ransomware_shred_has_unlinks(self) -> None:
        events = _collect_events("ransomware_shred", count=100)
        unlinks = [e for e in events if e["event_type"] == 4]
        assert len(unlinks) > 0

    def test_canary_touch_targets_canary_paths(self) -> None:
        canary = ["/tmp/test_canary/secret.txt"]
        events = _collect_events("canary_touch", count=10,
                                 canary_paths=canary)
        assert any(e["filename"] == canary[0] for e in events)

    def test_mixed_has_multiple_pids(self) -> None:
        events = _collect_events("mixed", count=200)
        pids = {e["pid"] for e in events}
        assert len(pids) >= 2, f"Mixed should have ≥2 PIDs, got {pids}"


class TestStreamerLifecycle:
    """Verify start / stop / error handling."""

    def test_stop_exits_cleanly(self) -> None:
        streamer = MockBPFStreamer(scenario="benign_compiler", events_per_sec=1000)
        streamer.register_callback(lambda e: None)
        t = threading.Thread(target=streamer.start, daemon=True)
        t.start()
        time.sleep(0.1)
        streamer.stop()
        t.join(timeout=2.0)
        assert not t.is_alive(), "Streamer thread did not exit after stop()"

    def test_unknown_scenario_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown scenario"):
            MockBPFStreamer(scenario="nonexistent_scenario")

    def test_no_callback_raises(self) -> None:
        streamer = MockBPFStreamer(scenario="benign_compiler")
        with pytest.raises(RuntimeError, match="No callback"):
            streamer.start()
