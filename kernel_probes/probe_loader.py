"""BCC loader for the AegisBPF kernel event stream.

BCC is imported lazily so this module remains importable on machines used for
mock-mode development where kernel headers or BCC are not installed.
"""

from __future__ import annotations

import ctypes
import os
import threading
from pathlib import Path
from typing import Any, Callable


class FileEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("tid", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("event_type", ctypes.c_uint),
        ("fd", ctypes.c_int),
        ("bytes_count", ctypes.c_ulonglong),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("new_filename", ctypes.c_char * 256),
        ("payload_sample", ctypes.c_ubyte * 64),
    ]


assert ctypes.sizeof(FileEvent) == 632, ctypes.sizeof(FileEvent)


def _decode(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _event_to_dict(raw: FileEvent) -> dict[str, Any]:
    payload = bytes(raw.payload_sample).rstrip(b"\0")
    return {
        "timestamp_ns": int(raw.timestamp_ns),
        "pid": int(raw.pid),
        "tid": int(raw.tid),
        "uid": int(raw.uid),
        "event_type": int(raw.event_type),
        "fd": int(raw.fd),
        "bytes_count": int(raw.bytes_count),
        "comm": _decode(bytes(raw.comm)),
        "filename": _decode(bytes(raw.filename)),
        "new_filename": _decode(bytes(raw.new_filename)),
        "payload_sample": payload,
    }


class BPFEventStreamer:
    def __init__(self, ringbuf_page_cnt: int = 64, ignore_pids: list[int] | None = None):
        if ringbuf_page_cnt <= 0:
            raise ValueError("ringbuf_page_cnt must be positive")
        self._bpf = None
        self._perf_buffer = None
        self._callback: Callable[[dict[str, Any]], None] | None = None
        self._stopped = threading.Event()
        self._closed = False
        try:
            from bcc import BPF
        except ImportError as exc:
            raise RuntimeError("BPFEventStreamer requires the BCC Python package") from exc

        source = Path(__file__).with_name("probes.bpf.c").read_text(encoding="utf-8")
        try:
            self._bpf = BPF(text=source)
            ignored = self._bpf["ignored_pids"]
            pids = {os.getpid(), *(ignore_pids or [])}
            for pid in pids:
                key = ctypes.c_uint(int(pid))
                ignored[key] = ctypes.c_ubyte(1)
            self._events = self._bpf["events"]
            self._page_cnt = int(ringbuf_page_cnt)
        except Exception:
            if self._bpf is not None:
                self._bpf.cleanup()
            raise

    def register_callback(self, callback_fn: Callable[[dict[str, Any]], None]) -> None:
        if not callable(callback_fn):
            raise TypeError("callback_fn must be callable")
        if self._closed:
            raise RuntimeError("streamer has been stopped")
        self._callback = callback_fn

        def _on_event(_cpu: int, data: int, _size: int) -> None:
            if self._callback is None:
                return
            raw = ctypes.cast(data, ctypes.POINTER(FileEvent)).contents
            self._callback(_event_to_dict(raw))

        self._events.open_perf_buffer(_on_event, page_cnt=self._page_cnt)
        self._perf_buffer = self._events

    def poll_once(self, timeout_ms: int = 100) -> None:
        if self._closed:
            return
        if self._callback is None:
            raise RuntimeError("register_callback must be called before polling")
        self._bpf.perf_buffer_poll(timeout=timeout_ms)

    def start_blocking_loop(self) -> None:
        if self._callback is None:
            raise RuntimeError("register_callback must be called before starting")
        self._stopped.clear()
        try:
            while not self._stopped.is_set():
                self._bpf.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        if self._closed:
            return
        self._stopped.set()
        self._closed = True
        if self._bpf is not None:
            self._bpf.cleanup()
            self._bpf = None


__all__ = ["BPFEventStreamer", "FileEvent"]
