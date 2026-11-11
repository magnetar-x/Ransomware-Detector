"""
engine/mock_streamer.py – High-fidelity synthetic kernel event generator.

Provides ``MockBPFStreamer``, a drop-in replacement for the real
``kernel.probe_loader.BPFEventStreamer`` so that the entire detection
engine can be developed and tested without root privileges or eBPF.

Usage
-----
    from engine.mock_streamer import MockBPFStreamer

    streamer = MockBPFStreamer(scenario="ransomware_inplace", events_per_sec=5000)
    streamer.register_callback(my_handler)
    streamer.start()          # blocks until stop() is called from another thread
"""

from __future__ import annotations

import math
import os
import random
import string
import struct
import threading
import time
from typing import Callable

from engine.config import (
    EVENT_CLOSE,
    EVENT_OPEN,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_WRITE,
    PAYLOAD_SAMPLE_SIZE,
)

# ---------------------------------------------------------------------------
# Canonical event factory  ─  every event dict produced by this module has
# the same shape, regardless of scenario.
# ---------------------------------------------------------------------------

def _make_event(
    *,
    pid: int,
    uid: int = 1000,
    event_type: int,
    comm: str = "mock_proc",
    filename: str = "",
    new_filename: str = "",
    fd: int = -1,
    bytes_count: int = 0,
    payload_sample: bytes = b"",
    ts_ns: int | None = None,
    tid: int | None = None,
) -> dict:
    """Return a canonical event dict matching Contract A (superset)."""
    now_ns = ts_ns if ts_ns is not None else time.monotonic_ns()
    return {
        "timestamp_ns": now_ns,
        "pid": pid,
        "tid": tid if tid is not None else pid,
        "uid": uid,
        "event_type": event_type,
        "fd": fd,
        "bytes_count": bytes_count,
        "comm": comm[:16],
        "filename": filename,
        "new_filename": new_filename,
        "payload_sample": payload_sample,
    }


# ---------------------------------------------------------------------------
# Payload generators
# ---------------------------------------------------------------------------

def _low_entropy_payload(size: int = PAYLOAD_SAMPLE_SIZE) -> bytes:
    """Return realistic low-entropy bytes (ASCII text-like)."""
    return bytes(random.choices(range(0x20, 0x7F), k=size))


def _high_entropy_payload(size: int = PAYLOAD_SAMPLE_SIZE) -> bytes:
    """Return near-random bytes simulating encrypted output."""
    return os.urandom(size)


# Known file magic headers for realistic OPEN events
_MAGIC_PDF = b"%PDF-1.7"
_MAGIC_ZIP = b"PK\x03\x04"
_MAGIC_PNG = b"\x89PNG\r\n\x1a\n"

# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------
# Each generator is a *generator function* that yields event dicts forever
# (the streamer pulls from it at the desired rate).
# ---------------------------------------------------------------------------

def _gen_benign_compiler(pid: int) -> "Generator[dict, None, None]":
    """
    Simulates ``gcc`` / ``rustc``: rapid OPEN → WRITE (low-entropy .o/.d
    files) → CLOSE.  Should produce **zero** alerts.
    """
    fd_counter = 100
    base_dir = "/tmp/build_output"
    extensions = [".o", ".d", ".s", ".ll", ".bc"]
    while True:
        ext = random.choice(extensions)
        fname = f"{base_dir}/{random.randint(1000,9999)}_unit{ext}"
        fd_counter += 1
        fd = fd_counter
        yield _make_event(pid=pid, event_type=EVENT_OPEN, comm="gcc",
                          filename=fname, fd=fd)
        # Several small low-entropy writes
        for _ in range(random.randint(1, 4)):
            payload = _low_entropy_payload()
            yield _make_event(pid=pid, event_type=EVENT_WRITE, comm="gcc",
                              filename=fname, fd=fd,
                              bytes_count=random.randint(128, 4096),
                              payload_sample=payload)
        yield _make_event(pid=pid, event_type=EVENT_CLOSE, comm="gcc",
                          filename=fname, fd=fd)


def _gen_benign_archiver(pid: int) -> "Generator[dict, None, None]":
    """
    Simulates ``tar`` / ``gzip``: OPEN → WRITE (high-entropy, but target
    is a ``.tar.gz``).  Stage-2 should whitelist these by extension.
    """
    fd_counter = 200
    base_dir = "/tmp/archives"
    while True:
        fd_counter += 1
        fd = fd_counter
        fname = f"{base_dir}/backup_{random.randint(1,999)}.tar.gz"
        yield _make_event(pid=pid, event_type=EVENT_OPEN, comm="tar",
                          filename=fname, fd=fd)
        for _ in range(random.randint(2, 8)):
            payload = _high_entropy_payload()   # compressed → high entropy
            yield _make_event(pid=pid, event_type=EVENT_WRITE, comm="tar",
                              filename=fname, fd=fd,
                              bytes_count=random.randint(4096, 65536),
                              payload_sample=payload)
        yield _make_event(pid=pid, event_type=EVENT_CLOSE, comm="tar",
                          filename=fname, fd=fd)


def _gen_ransomware_inplace(pid: int) -> "Generator[dict, None, None]":
    """
    In-Place Encryption Pattern:
      OPEN .docx → WRITE (high entropy, magic overwrite) → RENAME .docx.locked

    Tight loop across many victim files — should trigger ALERT quickly.
    """
    fd_counter = 300
    base_dir = "/home/user/docs"
    victim_extensions = [".docx", ".pdf", ".xlsx", ".txt", ".pptx"]
    ransom_suffix = ".locked"
    while True:
        fd_counter += 1
        fd = fd_counter
        ext = random.choice(victim_extensions)
        fname = f"{base_dir}/{''.join(random.choices(string.ascii_lowercase, k=6))}{ext}"
        new_fname = fname + ransom_suffix

        # OPEN – with realistic magic bytes as the "existing content"
        magic = _MAGIC_ZIP if ext in (".docx", ".xlsx", ".pptx") else _MAGIC_PDF
        yield _make_event(pid=pid, event_type=EVENT_OPEN, comm="evil_crypt",
                          filename=fname, fd=fd,
                          payload_sample=magic + _low_entropy_payload(
                              PAYLOAD_SAMPLE_SIZE - len(magic)))

        # WRITE – high-entropy overwrite of the magic region
        yield _make_event(pid=pid, event_type=EVENT_WRITE, comm="evil_crypt",
                          filename=fname, fd=fd,
                          bytes_count=random.randint(4096, 65536),
                          payload_sample=_high_entropy_payload())

        # RENAME – .docx → .docx.locked
        yield _make_event(pid=pid, event_type=EVENT_RENAME, comm="evil_crypt",
                          filename=fname, new_filename=new_fname, fd=fd)


def _gen_ransomware_shred(pid: int) -> "Generator[dict, None, None]":
    """
    Copy-and-Shred Pattern:
      OPEN(A) → WRITE(B, high entropy) → UNLINK(A)
    """
    fd_counter = 400
    base_dir = "/home/user/photos"
    while True:
        fd_counter += 1
        fd = fd_counter
        name_stem = ''.join(random.choices(string.ascii_lowercase, k=5))
        file_a = f"{base_dir}/{name_stem}.jpg"
        file_b = f"{base_dir}/{name_stem}.jpg.enc"

        yield _make_event(pid=pid, event_type=EVENT_OPEN, comm="shredder",
                          filename=file_a, fd=fd)
        yield _make_event(pid=pid, event_type=EVENT_WRITE, comm="shredder",
                          filename=file_b, fd=fd + 1,
                          bytes_count=random.randint(4096, 131072),
                          payload_sample=_high_entropy_payload())
        yield _make_event(pid=pid, event_type=EVENT_UNLINK, comm="shredder",
                          filename=file_a)


def _gen_canary_touch(pid: int, canary_paths: list[str] | None = None
                      ) -> "Generator[dict, None, None]":
    """
    Single deliberate WRITE to a canary honeyfile.  Should trigger an
    **instant** +100 score and ALERT on the first event.
    """
    if not canary_paths:
        # Fallback to the default canary names used by CanaryManager
        canary_paths = [
            "/tmp/aegis_canary_zone/.~lock_financial_backup.xlsx",
            "/tmp/aegis_canary_zone/00_passwords_vault.kdbx",
        ]
    idx = 0
    while True:
        path = canary_paths[idx % len(canary_paths)]
        yield _make_event(pid=pid, event_type=EVENT_WRITE, comm="sneaky",
                          filename=path, fd=50,
                          bytes_count=64,
                          payload_sample=_high_entropy_payload())
        idx += 1
        # Also try rename / unlink on canaries to verify coverage
        yield _make_event(pid=pid, event_type=EVENT_RENAME, comm="sneaky",
                          filename=path,
                          new_filename=path + ".bak")
        yield _make_event(pid=pid, event_type=EVENT_UNLINK, comm="sneaky",
                          filename=path)


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

_SCENARIO_FACTORIES: dict[str, list[tuple[Callable, dict]]] = {
    # Each value is a list of (generator_factory, extra_kwargs).
    # Multiple entries per scenario allow multiple PIDs.
    "benign_compiler": [
        (_gen_benign_compiler, {"pid": 1001}),
        (_gen_benign_compiler, {"pid": 1002}),
    ],
    "benign_archiver": [
        (_gen_benign_archiver, {"pid": 2001}),
        (_gen_benign_archiver, {"pid": 2002}),
    ],
    "ransomware_inplace": [
        (_gen_ransomware_inplace, {"pid": 6660}),
    ],
    "ransomware_shred": [
        (_gen_ransomware_shred, {"pid": 6670}),
    ],
    "canary_touch": [
        (_gen_canary_touch, {"pid": 6680}),
    ],
    "mixed": [
        (_gen_benign_compiler, {"pid": 1001}),
        (_gen_benign_archiver, {"pid": 2001}),
        (_gen_ransomware_inplace, {"pid": 6660}),
    ],
}

AVAILABLE_SCENARIOS: list[str] = sorted(_SCENARIO_FACTORIES.keys())


# ---------------------------------------------------------------------------
# MockBPFStreamer – the public interface
# ---------------------------------------------------------------------------

class MockBPFStreamer:
    """
    Drop-in replacement for ``kernel.probe_loader.BPFEventStreamer``.

    Parameters
    ----------
    scenario : str
        One of :data:`AVAILABLE_SCENARIOS`.
    events_per_sec : int
        Target event throughput.  The streamer sleeps between bursts to
        approximate this rate.
    canary_paths : list[str] | None
        Explicit canary file paths (forwarded to canary_touch scenario).
    """

    def __init__(
        self,
        scenario: str = "benign_compiler",
        events_per_sec: int = 5000,
        canary_paths: list[str] | None = None,
    ) -> None:
        if scenario not in _SCENARIO_FACTORIES:
            raise ValueError(
                f"Unknown scenario {scenario!r}. "
                f"Available: {AVAILABLE_SCENARIOS}"
            )
        self._scenario = scenario
        self._eps = max(1, events_per_sec)
        self._canary_paths = canary_paths
        self._callback: Callable[[dict], None] | None = None
        self._stop_event = threading.Event()
        self._generators: list = []

    # -- public API (matches BPFEventStreamer interface) ---------------------

    def register_callback(self, cb: Callable[[dict], None]) -> None:
        """Register the function that receives each event dict."""
        self._callback = cb

    def start(self) -> None:
        """
        Block the calling thread, emitting events at the configured rate
        until :meth:`stop` is called from another thread.
        """
        if self._callback is None:
            raise RuntimeError("No callback registered – call register_callback() first")

        # Build generators for the chosen scenario
        self._generators = []
        for factory, kwargs in _SCENARIO_FACTORIES[self._scenario]:
            kw = dict(kwargs)
            if factory is _gen_canary_touch and self._canary_paths:
                kw["canary_paths"] = self._canary_paths
            self._generators.append(factory(**kw))

        n_gens = len(self._generators)
        interval = 1.0 / self._eps     # seconds between individual events
        burst_size = max(1, self._eps // 100)  # emit in small bursts for efficiency
        burst_interval = burst_size * interval
        gen_idx = 0

        while not self._stop_event.is_set():
            burst_start = time.monotonic()
            for _ in range(burst_size):
                if self._stop_event.is_set():
                    return
                evt = next(self._generators[gen_idx % n_gens])
                self._callback(evt)
                gen_idx += 1
            # Sleep to maintain target rate
            elapsed = time.monotonic() - burst_start
            sleep_time = burst_interval - elapsed
            if sleep_time > 0:
                self._stop_event.wait(timeout=sleep_time)

    def stop(self) -> None:
        """Signal the streamer to exit its run loop."""
        self._stop_event.set()
