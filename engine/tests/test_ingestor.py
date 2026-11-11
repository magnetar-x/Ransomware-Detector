"""
engine/tests/test_ingestor.py – Unit tests for EventIngestor.

Verifies:
  1. Mock-mode ingestion delivers events with correct canonical shape.
  2. Live-mode raises RuntimeError when kernel module is absent.
  3. Invalid mode raises ValueError.
  4. FsEvent ctypes struct has the correct size (304 bytes).
  5. _cstruct_to_dict produces the expected canonical dict.
"""

from __future__ import annotations

import ctypes
import threading
import time

import pytest

from engine.ingestor import EventIngestor, FsEvent, _cstruct_to_dict


class TestFsEventStruct:
    """Verify the ctypes struct matches common/event_defs.h layout."""

    def test_size_is_304(self) -> None:
        assert ctypes.sizeof(FsEvent) == 304

    def test_field_offsets(self) -> None:
        assert FsEvent.ts.offset == 0
        assert FsEvent.pid.offset == 8
        assert FsEvent.uid.offset == 12
        assert FsEvent.syscall_type.offset == 16
        # bytes_req at offset 24 (after 4 bytes padding at 20)
        assert FsEvent.bytes_req.offset == 24
        assert FsEvent.comm.offset == 32
        assert FsEvent.filename.offset == 48

    def test_cstruct_to_dict(self) -> None:
        raw = FsEvent()
        raw.ts = 1234567890
        raw.pid = 42
        raw.uid = 1000
        raw.syscall_type = 2  # EVENT_WRITE
        raw.bytes_req = 4096
        raw.comm = b"test_proc\x00\x00\x00\x00\x00\x00\x00"
        raw.filename = b"/tmp/test.txt" + b"\x00" * (256 - 13)

        d = _cstruct_to_dict(raw)
        assert d["timestamp_ns"] == 1234567890
        assert d["pid"] == 42
        assert d["tid"] == 42           # defaults to pid
        assert d["uid"] == 1000
        assert d["event_type"] == 2
        assert d["fd"] == -1            # not in C struct
        assert d["bytes_count"] == 4096
        assert d["comm"] == "test_proc"
        assert d["filename"] == "/tmp/test.txt"
        assert d["new_filename"] == ""
        assert d["payload_sample"] == b""


class TestIngestorMockMode:
    """Verify mock-mode ingestion works end-to-end."""

    def test_receives_events(self, collector) -> None:
        ingestor = EventIngestor(
            mode="mock",
            callback=collector,
            mock_scenario="benign_compiler",
            mock_eps=50_000,
        )
        t = threading.Thread(target=ingestor.start, daemon=True)
        t.start()
        # Wait for some events
        deadline = time.monotonic() + 3.0
        while len(collector) < 100 and time.monotonic() < deadline:
            time.sleep(0.05)
        ingestor.stop()
        t.join(timeout=2.0)
        assert len(collector) >= 100

    def test_all_scenarios_ingestible(self, collector) -> None:
        """Every scenario must be consumable through the ingestor."""
        from engine.mock_streamer import AVAILABLE_SCENARIOS
        for scenario in AVAILABLE_SCENARIOS:
            coll = type(collector)()  # fresh collector
            ingestor = EventIngestor(
                mode="mock", callback=coll,
                mock_scenario=scenario, mock_eps=50_000,
            )
            t = threading.Thread(target=ingestor.start, daemon=True)
            t.start()
            deadline = time.monotonic() + 3.0
            while len(coll) < 20 and time.monotonic() < deadline:
                time.sleep(0.05)
            ingestor.stop()
            t.join(timeout=2.0)
            assert len(coll) >= 20, f"Scenario {scenario} produced only {len(coll)} events"


class TestIngestorErrors:
    """Verify error handling."""

    def test_invalid_mode(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            EventIngestor(mode="invalid", callback=lambda e: None)

    def test_live_mode_without_kernel_raises(self) -> None:
        ingestor = EventIngestor(mode="live", callback=lambda e: None)
        with pytest.raises(RuntimeError, match="kernel.probe_loader"):
            ingestor.start()

    def test_no_callback_raises(self) -> None:
        ingestor = EventIngestor(mode="mock")
        with pytest.raises(RuntimeError, match="callback"):
            ingestor.start()
