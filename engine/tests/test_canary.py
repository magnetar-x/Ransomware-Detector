"""
engine/tests/test_canary.py – Unit tests for CanaryManager.

Covers:
  • Decoy file deployment and on-disk presence
  • O(1) is_canary lookup
  • Zero-tolerance tripwire: WRITE / RENAME / UNLINK → +100 score
  • Non-canary files return 0.0
  • Cleanup removes files and clears state
"""

from __future__ import annotations

import os

import pytest

from engine.config import (
    CANARY_SCORE_INSTANT,
    EVENT_OPEN,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_WRITE,
)
from engine.heuristics.canary import CanaryManager
from engine.state_tracker import PIDState


@pytest.fixture
def canary(tmp_path):
    """Deploy canaries in a per-test temp dir, cleanup after."""
    mgr = CanaryManager(deploy_dir=str(tmp_path / "canary"))
    mgr.deploy()
    yield mgr
    mgr.cleanup()


class TestDeployment:
    def test_files_created_on_disk(self, canary: CanaryManager) -> None:
        for path in canary.canary_paths:
            assert os.path.isfile(path), f"Canary not on disk: {path}"

    def test_at_least_4_decoys(self, canary: CanaryManager) -> None:
        assert len(canary.canary_paths) >= 4

    def test_files_have_content(self, canary: CanaryManager) -> None:
        for path in canary.canary_paths:
            assert os.path.getsize(path) > 0

    def test_is_canary_true(self, canary: CanaryManager) -> None:
        for path in canary.canary_paths:
            assert canary.is_canary(path)

    def test_is_canary_false(self, canary: CanaryManager) -> None:
        assert not canary.is_canary("/tmp/definitely_not_a_canary.txt")
        assert not canary.is_canary("/etc/passwd")


class TestTripwire:
    def _make_event(self, event_type: int, filename: str,
                    new_filename: str = "") -> dict:
        return {
            "event_type": event_type,
            "pid": 999,
            "comm": "evil",
            "filename": filename,
            "new_filename": new_filename,
        }

    def test_write_to_canary_instant_100(self, canary: CanaryManager) -> None:
        path = next(iter(canary.canary_paths))
        state = PIDState(pid=999)
        evt = self._make_event(EVENT_WRITE, path)
        delta = canary.check_event(evt, state)
        assert delta == CANARY_SCORE_INSTANT

    def test_rename_canary_instant_100(self, canary: CanaryManager) -> None:
        path = next(iter(canary.canary_paths))
        state = PIDState(pid=999)
        evt = self._make_event(EVENT_RENAME, path, path + ".bak")
        delta = canary.check_event(evt, state)
        assert delta == CANARY_SCORE_INSTANT

    def test_unlink_canary_instant_100(self, canary: CanaryManager) -> None:
        path = next(iter(canary.canary_paths))
        state = PIDState(pid=999)
        evt = self._make_event(EVENT_UNLINK, path)
        delta = canary.check_event(evt, state)
        assert delta == CANARY_SCORE_INSTANT

    def test_open_canary_no_score(self, canary: CanaryManager) -> None:
        """OPEN is not a destructive op — should not trigger."""
        path = next(iter(canary.canary_paths))
        evt = self._make_event(EVENT_OPEN, path)
        delta = canary.check_event(evt)
        assert delta == 0.0

    def test_write_non_canary_no_score(self, canary: CanaryManager) -> None:
        evt = self._make_event(EVENT_WRITE, "/home/user/normal.txt")
        delta = canary.check_event(evt)
        assert delta == 0.0

    def test_triggered_heuristic_appended(self, canary: CanaryManager) -> None:
        path = next(iter(canary.canary_paths))
        state = PIDState(pid=999)
        canary.check_event(
            self._make_event(EVENT_WRITE, path), state,
        )
        assert any("CANARY_TRIPWIRE" in h for h in state.triggered_heuristics)


class TestCleanup:
    def test_cleanup_removes_files(self, tmp_path) -> None:
        mgr = CanaryManager(deploy_dir=str(tmp_path / "canary_clean"))
        mgr.deploy()
        paths = list(mgr.canary_paths)
        assert all(os.path.isfile(p) for p in paths)

        mgr.cleanup()
        assert not os.path.isdir(str(tmp_path / "canary_clean"))
        assert len(mgr.canary_paths) == 0

    def test_cleanup_idempotent(self, tmp_path) -> None:
        mgr = CanaryManager(deploy_dir=str(tmp_path / "canary_idem"))
        mgr.deploy()
        mgr.cleanup()
        mgr.cleanup()  # should not raise
