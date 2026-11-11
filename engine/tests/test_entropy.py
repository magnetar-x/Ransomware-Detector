"""
engine/tests/test_entropy.py – Unit tests for dual-stage Shannon entropy.

Covers:
  • shannon_entropy correctness (known values)
  • Stage 1: inline entropy on 64-byte payloads
  • Magic-byte stash on OPEN → magic-overwrite detection on WRITE (+35)
  • Stage 2: on-disk entropy with archive-extension bypass
  • Edge cases (empty data, short files)
"""

from __future__ import annotations

import math
import os

import pytest

from engine.config import (
    ENTROPY_DISK_HIGH,
    ENTROPY_INLINE_HIGH,
    EVENT_CLOSE,
    EVENT_OPEN,
    EVENT_WRITE,
    SCORE_DISK_ENTROPY,
    SCORE_MAGIC_OVERWRITE,
)
from engine.heuristics.entropy import (
    check_disk_entropy,
    check_inline_entropy,
    shannon_entropy,
)
from engine.state_tracker import PIDState


# ---------------------------------------------------------------------------
# shannon_entropy unit tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty(self) -> None:
        assert shannon_entropy(b"") == 0.0

    def test_single_byte(self) -> None:
        # One byte → only one value, P=1 → H=0
        assert shannon_entropy(b"\x42") == 0.0

    def test_uniform_bytes(self) -> None:
        # All 256 values once → H = log₂(256) = 8.0
        data = bytes(range(256))
        h = shannon_entropy(data)
        assert abs(h - 8.0) < 0.001

    def test_two_distinct_equal(self) -> None:
        # 50/50 split → H = 1.0
        data = b"\x00\x01" * 32
        h = shannon_entropy(data)
        assert abs(h - 1.0) < 0.001

    def test_low_entropy_text(self) -> None:
        # Repetitive text → low entropy
        data = (b"int x = 0;\n" * 6)[:64]
        h = shannon_entropy(data)
        assert h < 4.0, f"Expected low entropy, got {h}"

    def test_high_entropy_random(self) -> None:
        # os.urandom → near-maximum entropy for 64 bytes (max ~6.0)
        data = os.urandom(64)
        h = shannon_entropy(data)
        assert h > 4.5, f"Expected high entropy from random bytes, got {h}"

    def test_high_entropy_4096_random(self) -> None:
        # 4096 random bytes → entropy close to 8.0
        data = os.urandom(4096)
        h = shannon_entropy(data)
        assert h > 7.5


# ---------------------------------------------------------------------------
# Stage 1 — check_inline_entropy
# ---------------------------------------------------------------------------

class TestInlineEntropy:
    def _make_open_event(self, filename: str, magic: bytes = b"") -> dict:
        payload = magic + b"\x00" * max(0, 64 - len(magic)) if magic else b""
        return {
            "event_type": EVENT_OPEN,
            "filename": filename,
            "payload_sample": payload,
            "pid": 100,
        }

    def _make_write_event(self, filename: str, payload: bytes) -> dict:
        return {
            "event_type": EVENT_WRITE,
            "filename": filename,
            "payload_sample": payload,
            "bytes_count": len(payload),
            "pid": 100,
        }

    def test_open_stashes_magic(self) -> None:
        state = PIDState(pid=100)
        evt = self._make_open_event("/tmp/test.pdf", magic=b"%PDF-1.7")
        delta = check_inline_entropy(evt, state)
        assert delta == 0.0
        assert "/tmp/test.pdf" in state.magic_bytes

    def test_open_unknown_magic_not_stashed(self) -> None:
        state = PIDState(pid=100)
        evt = self._make_open_event("/tmp/test.txt", magic=b"AAAA")
        check_inline_entropy(evt, state)
        assert "/tmp/test.txt" not in state.magic_bytes

    def test_write_low_entropy_no_score(self) -> None:
        state = PIDState(pid=100)
        payload = (b"int x = 0;\n" * 6)[:64]
        evt = self._make_write_event("/tmp/test.c", payload)
        delta = check_inline_entropy(evt, state)
        assert delta == 0.0
        assert state.last_write_entropy < ENTROPY_INLINE_HIGH

    def test_magic_overwrite_scores_35(self) -> None:
        state = PIDState(pid=100)
        # Step 1: OPEN with PDF magic
        open_evt = self._make_open_event("/tmp/report.pdf", magic=b"%PDF-1.7")
        check_inline_entropy(open_evt, state)

        # Step 2: WRITE high-entropy data to same file
        write_evt = self._make_write_event("/tmp/report.pdf", os.urandom(64))
        delta = check_inline_entropy(write_evt, state)
        assert delta == SCORE_MAGIC_OVERWRITE  # +35.0

    def test_high_entropy_without_magic_no_bonus(self) -> None:
        state = PIDState(pid=100)
        # No OPEN → no stashed magic
        write_evt = self._make_write_event("/tmp/new_file.bin", os.urandom(64))
        delta = check_inline_entropy(write_evt, state)
        assert delta == 0.0
        assert state.last_write_entropy > ENTROPY_INLINE_HIGH

    def test_empty_payload_no_crash(self) -> None:
        state = PIDState(pid=100)
        evt = self._make_write_event("/tmp/x.txt", b"")
        delta = check_inline_entropy(evt, state)
        assert delta == 0.0
        assert state.last_write_entropy == 0.0


# ---------------------------------------------------------------------------
# Stage 2 — check_disk_entropy
# ---------------------------------------------------------------------------

class TestDiskEntropy:
    def test_high_entropy_file_scores_30(self, tmp_path) -> None:
        fpath = str(tmp_path / "encrypted.dat")
        with open(fpath, "wb") as f:
            f.write(os.urandom(4096))
        state = PIDState(pid=100)
        delta = check_disk_entropy(fpath, state)
        assert delta == SCORE_DISK_ENTROPY  # +30.0

    def test_low_entropy_file_no_score(self, tmp_path) -> None:
        fpath = str(tmp_path / "normal.txt")
        with open(fpath, "wb") as f:
            f.write(b"Hello world!\n" * 300)
        state = PIDState(pid=100)
        delta = check_disk_entropy(fpath, state)
        assert delta == 0.0

    def test_archive_extension_bypassed(self, tmp_path) -> None:
        fpath = str(tmp_path / "data.tar.gz")
        with open(fpath, "wb") as f:
            f.write(os.urandom(4096))
        state = PIDState(pid=100)
        delta = check_disk_entropy(fpath, state)
        assert delta == 0.0  # whitelisted extension

    def test_zip_extension_bypassed(self, tmp_path) -> None:
        fpath = str(tmp_path / "archive.zip")
        with open(fpath, "wb") as f:
            f.write(os.urandom(4096))
        state = PIDState(pid=100)
        assert check_disk_entropy(fpath, state) == 0.0

    def test_nonexistent_file_no_crash(self) -> None:
        state = PIDState(pid=100)
        delta = check_disk_entropy("/nonexistent/path.dat", state)
        assert delta == 0.0

    def test_small_file_no_score(self, tmp_path) -> None:
        fpath = str(tmp_path / "tiny.dat")
        with open(fpath, "wb") as f:
            f.write(os.urandom(32))  # < 64 bytes
        state = PIDState(pid=100)
        assert check_disk_entropy(fpath, state) == 0.0
