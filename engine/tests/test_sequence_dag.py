"""
engine/tests/test_sequence_dag.py – Unit tests for Behavioral Syscall Sequence DAG.

Covers:
  • In-Place Encryption Pattern: OPEN -> WRITE (high entropy) -> RENAME (extension change)
  • Copy-and-Shred Pattern: OPEN(A) -> WRITE(B, high entropy) -> UNLINK(A)
  • Exponential scoring: ΔS = 10 * 1.5^C
  • Low entropy writes do not complete destructive cycles
  • Same extension renames do not trigger Pattern A
  • Stale entries outside the 2.0s window are pruned
"""

from __future__ import annotations

import time
import pytest

from engine.config import (
    DAG_BASE_SCORE,
    DAG_EXPONENT_BASE,
    EVENT_OPEN,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_WRITE,
)
from engine.heuristics.sequence_dag import check_sequence
from engine.state_tracker import PIDState


def _make_event(
    event_type: int,
    filename: str,
    new_filename: str = "",
    pid: int = 500,
) -> dict:
    return {
        "event_type": event_type,
        "pid": pid,
        "comm": "test_proc",
        "filename": filename,
        "new_filename": new_filename,
    }


class TestInPlaceEncryption:
    def test_inplace_single_cycle(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        # Step 1: OPEN
        e_open = _make_event(EVENT_OPEN, "/docs/report.docx")
        score = check_sequence(e_open, state, now=now)
        assert score == 0.0

        # Step 2: WRITE with high entropy
        state.last_write_entropy = 5.8
        e_write = _make_event(EVENT_WRITE, "/docs/report.docx")
        score = check_sequence(e_write, state, now=now + 0.01)
        assert score == 0.0

        # Step 3: RENAME with new extension
        e_rename = _make_event(
            EVENT_RENAME, "/docs/report.docx", "/docs/report.docx.locked"
        )
        score = check_sequence(e_rename, state, now=now + 0.02)

        # Expected score: 10 * 1.5^1 = 15.0
        expected = DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** 1)
        assert abs(score - expected) < 1e-3
        assert state.dag_cycles == 1
        assert any("DESTRUCTIVE_SEQUENCE_DAG" in h for h in state.triggered_heuristics)

    def test_inplace_exponential_scoring(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        scores = []
        for i in range(3):
            fn = f"/docs/file_{i}.txt"
            fn_enc = f"/docs/file_{i}.txt.enc"

            check_sequence(_make_event(EVENT_OPEN, fn), state, now=now + i * 0.1)
            state.last_write_entropy = 5.9
            check_sequence(_make_event(EVENT_WRITE, fn), state, now=now + i * 0.1 + 0.01)
            sc = check_sequence(
                _make_event(EVENT_RENAME, fn, fn_enc), state, now=now + i * 0.1 + 0.02
            )
            scores.append(sc)

        assert state.dag_cycles == 3
        assert abs(scores[0] - (DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** 1))) < 1e-3
        assert abs(scores[1] - (DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** 2))) < 1e-3
        assert abs(scores[2] - (DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** 3))) < 1e-3

    def test_low_entropy_write_no_cycle(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        check_sequence(_make_event(EVENT_OPEN, "/docs/doc.txt"), state, now=now)
        state.last_write_entropy = 2.1  # low entropy
        check_sequence(_make_event(EVENT_WRITE, "/docs/doc.txt"), state, now=now + 0.01)
        score = check_sequence(
            _make_event(EVENT_RENAME, "/docs/doc.txt", "/docs/doc.txt.bak"),
            state,
            now=now + 0.02,
        )
        assert score == 0.0
        assert state.dag_cycles == 0

    def test_same_extension_no_cycle(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        check_sequence(_make_event(EVENT_OPEN, "/docs/doc.txt"), state, now=now)
        state.last_write_entropy = 5.8
        check_sequence(_make_event(EVENT_WRITE, "/docs/doc.txt"), state, now=now + 0.01)
        score = check_sequence(
            _make_event(EVENT_RENAME, "/docs/doc.txt", "/docs/doc_new.txt"),
            state,
            now=now + 0.02,
        )
        assert score == 0.0
        assert state.dag_cycles == 0


class TestCopyAndShred:
    def test_copy_and_shred_pattern(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        # Step 1: OPEN File A
        check_sequence(_make_event(EVENT_OPEN, "/photos/pic.jpg"), state, now=now)

        # Step 2: WRITE File B (high entropy)
        state.last_write_entropy = 5.8
        check_sequence(_make_event(EVENT_WRITE, "/photos/pic.jpg.enc"), state, now=now + 0.01)

        # Step 3: UNLINK File A
        score = check_sequence(_make_event(EVENT_UNLINK, "/photos/pic.jpg"), state, now=now + 0.02)

        expected = DAG_BASE_SCORE * (DAG_EXPONENT_BASE ** 1)
        assert abs(score - expected) < 1e-3
        assert state.dag_cycles == 1
        assert any("OPEN→WRITE(other)→UNLINK" in h for h in state.triggered_heuristics)

    def test_unlink_without_prior_open_no_cycle(self) -> None:
        state = PIDState(pid=500)
        now = time.monotonic()

        state.last_write_entropy = 5.8
        check_sequence(_make_event(EVENT_WRITE, "/photos/out.enc"), state, now=now)
        score = check_sequence(_make_event(EVENT_UNLINK, "/photos/never_opened.jpg"), state, now=now + 0.01)
        assert score == 0.0
        assert state.dag_cycles == 0


class TestWindowExpiration:
    def test_expired_open_does_not_complete_cycle(self) -> None:
        state = PIDState(pid=500)
        t0 = time.monotonic()

        check_sequence(_make_event(EVENT_OPEN, "/data.bin"), state, now=t0)
        state.last_write_entropy = 5.8
        check_sequence(_make_event(EVENT_WRITE, "/data.bin"), state, now=t0 + 0.01)

        # Event occurs 3 seconds later (> DAG_WINDOW_SEC = 2.0s)
        score = check_sequence(
            _make_event(EVENT_RENAME, "/data.bin", "/data.bin.locked"),
            state,
            now=t0 + 3.0,
        )
        assert score == 0.0
        assert state.dag_cycles == 0
