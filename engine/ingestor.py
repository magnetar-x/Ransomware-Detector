"""
engine/ingestor.py – Dual-mode event consumer.

Provides ``EventIngestor`` which can switch between:
  • **live mode** – imports ``BPFEventStreamer`` from ``kernel.probe_loader``
    and translates the lean C-struct-based events into the canonical
    superset dict used by the engine.
  • **mock mode** – uses ``engine.mock_streamer.MockBPFStreamer`` for
    standalone development and testing.

Both modes deliver events through the same ``callback(event_dict)``
interface so every downstream module is agnostic to the source.

C struct reference  (from ``common/event_defs.h``):
    struct fs_event_t {                 // offset  size
        unsigned long long ts;          //   0       8
        unsigned int       pid;         //   8       4
        unsigned int       uid;         //  12       4
        int                syscall_type;//  16       4
        /* 4 bytes padding */           //  20       4
        unsigned long      bytes_req;   //  24       8
        char comm[16];                  //  32      16
        char filename[256];             //  48     256
    };                                  //         304 total
"""

from __future__ import annotations

import ctypes
import logging
import threading
from typing import Callable

from engine.config import (
    MAX_FILENAME_LEN,
    TASK_COMM_LEN,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ctypes mirror of ``struct fs_event_t``  (common/event_defs.h)
# ---------------------------------------------------------------------------

class FsEvent(ctypes.Structure):
    """
    Python ctypes mapping of the kernel-side ``struct fs_event_t``.

    Field order and types match the C definition exactly so that
    ``ctypes.sizeof(FsEvent) == 304`` on x86-64.
    """
    _fields_ = [
        ("ts",           ctypes.c_ulonglong),       # unsigned long long  (8)
        ("pid",          ctypes.c_uint),             # unsigned int        (4)
        ("uid",          ctypes.c_uint),             # unsigned int        (4)
        ("syscall_type", ctypes.c_int),              # int                 (4)
        # --- 4 bytes implicit padding before the next 8-byte-aligned field ---
        ("bytes_req",    ctypes.c_ulong),            # unsigned long       (8)
        ("comm",         ctypes.c_char * TASK_COMM_LEN),      # char[16]
        ("filename",     ctypes.c_char * MAX_FILENAME_LEN),   # char[256]
    ]


# Compile-time sanity – ensure our struct agrees with the C layout.
assert ctypes.sizeof(FsEvent) == 304, (
    f"FsEvent size mismatch: expected 304, got {ctypes.sizeof(FsEvent)}"
)


def _cstruct_to_dict(raw: FsEvent) -> dict:
    """
    Convert a raw ``FsEvent`` ctypes instance into the canonical event dict.

    The C struct is leaner than the full Contract-A superset (no ``tid``,
    ``fd``, ``new_filename``, ``payload_sample``).  Missing fields are
    filled with safe defaults so downstream heuristics always see a
    uniform shape.
    """
    return {
        "timestamp_ns": raw.ts,
        "pid":          raw.pid,
        "tid":          raw.pid,                    # no tid in C struct → default to pid
        "uid":          raw.uid,
        "event_type":   raw.syscall_type,
        "fd":           -1,                         # not in C struct
        "bytes_count":  raw.bytes_req,
        "comm":         raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "filename":     raw.filename.decode("utf-8", errors="replace").rstrip("\x00"),
        "new_filename": "",                         # not in C struct
        "payload_sample": b"",                      # not in C struct
    }


# ---------------------------------------------------------------------------
# EventIngestor – the public dual-mode consumer
# ---------------------------------------------------------------------------

class EventIngestor:
    """
    Dual-mode event consumer.

    Parameters
    ----------
    mode : ``"live"`` | ``"mock"``
        ``"live"`` – import ``BPFEventStreamer`` from ``kernel.probe_loader``.
        ``"mock"`` – use ``engine.mock_streamer.MockBPFStreamer``.
    callback : callable
        Function that receives each normalised event dict.
    mock_scenario : str
        Scenario name forwarded to ``MockBPFStreamer`` (ignored in live mode).
    mock_eps : int
        Events-per-second for the mock streamer (ignored in live mode).
    canary_paths : list[str] | None
        Canary file paths forwarded to the mock streamer.
    """

    def __init__(
        self,
        mode: str = "mock",
        callback: Callable[[dict], None] | None = None,
        mock_scenario: str = "benign_compiler",
        mock_eps: int = 5000,
        canary_paths: list[str] | None = None,
    ) -> None:
        if mode not in ("live", "mock"):
            raise ValueError(f"mode must be 'live' or 'mock', got {mode!r}")
        self._mode = mode
        self._callback = callback
        self._mock_scenario = mock_scenario
        self._mock_eps = mock_eps
        self._canary_paths = canary_paths
        self._streamer = None
        self._stop_event = threading.Event()

    # -- public API ---------------------------------------------------------

    def start(self) -> None:
        """
        Block the calling thread, consuming events until :meth:`stop` is
        called from another thread.
        """
        if self._callback is None:
            raise RuntimeError("No callback set – pass one to __init__ or set .callback")

        if self._mode == "mock":
            self._start_mock()
        else:
            self._start_live()

    def stop(self) -> None:
        """Signal the ingestor (and its underlying streamer) to shut down."""
        self._stop_event.set()
        if self._streamer is not None:
            self._streamer.stop()

    # -- private: mock path -------------------------------------------------

    def _start_mock(self) -> None:
        from engine.mock_streamer import MockBPFStreamer

        logger.info(
            "Starting MockBPFStreamer  scenario=%s  eps=%d",
            self._mock_scenario, self._mock_eps,
        )
        self._streamer = MockBPFStreamer(
            scenario=self._mock_scenario,
            events_per_sec=self._mock_eps,
            canary_paths=self._canary_paths,
        )
        # Mock events are already in canonical dict form → pass directly
        self._streamer.register_callback(self._callback)
        self._streamer.start()  # blocks

    # -- private: live / BCC path -------------------------------------------

    def _start_live(self) -> None:
        try:
            from kernel.probe_loader import BPFEventStreamer  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError(
                "Live mode requires the 'kernel.probe_loader' module "
                "(Role 1).  Use --mock for standalone testing."
            ) from exc

        logger.info("Starting live BPFEventStreamer")
        self._streamer = BPFEventStreamer()

        def _on_live_event(ctx, data, size):  # noqa: ARG001 – BCC callback signature
            """Receive raw ring-buffer bytes and convert to canonical dict."""
            evt = ctypes.cast(data, ctypes.POINTER(FsEvent)).contents
            self._callback(_cstruct_to_dict(evt))

        self._streamer.register_callback(_on_live_event)
        self._streamer.start()  # blocks
