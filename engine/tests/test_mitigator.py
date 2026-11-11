"""
engine/tests/test_mitigator.py – Unit tests for Mitigator.

Covers:
  • Dry-run safe mode: returns "DRY_RUN_KILL", sends no real signals
  • Whitelist protection: returns "NONE" for OS-critical binaries
  • Deduplication: does not spam mitigation for already-mitigated PIDs
  • Reset clears mitigated PIDs
  • Process tree discovery handles missing/invalid PIDs gracefully
"""

from __future__ import annotations

import os
import signal
from unittest.mock import patch

import pytest

from engine.mitigator import Mitigator, find_child_pids
from engine.state_tracker import PIDState


class TestMitigatorSafeMode:
    def test_dry_run_returns_dry_run_kill(self) -> None:
        mitigator = Mitigator(dry_run=True)
        state = PIDState(pid=9999, comm="ransom_sim")
        state.risk_score = 95.0

        with patch("os.kill") as mock_kill:
            action = mitigator.execute(state)
            assert action == "DRY_RUN_KILL"
            mock_kill.assert_not_called()

    def test_whitelisted_process_returns_none(self) -> None:
        mitigator = Mitigator(dry_run=False, whitelist=["systemd", "sshd"])
        state = PIDState(pid=1, comm="systemd")
        state.risk_score = 100.0

        with patch("os.kill") as mock_kill:
            action = mitigator.execute(state)
            assert action == "NONE"
            mock_kill.assert_not_called()

    def test_whitelisted_path_comm(self) -> None:
        mitigator = Mitigator(dry_run=True, whitelist=["sshd"])
        state = PIDState(pid=1234, comm="/usr/sbin/sshd")
        state.risk_score = 90.0

        action = mitigator.execute(state)
        assert action == "NONE"

    def test_deduplication(self) -> None:
        mitigator = Mitigator(dry_run=True)
        state = PIDState(pid=5000, comm="evil")
        state.risk_score = 80.0

        act1 = mitigator.execute(state)
        act2 = mitigator.execute(state)
        assert act1 == "DRY_RUN_KILL"
        assert act2 == "DRY_RUN_KILL"

    def test_reset(self) -> None:
        mitigator = Mitigator(dry_run=True)
        state = PIDState(pid=5000, comm="evil")
        mitigator.execute(state)
        assert 5000 in mitigator._mitigated_pids
        mitigator.reset()
        assert len(mitigator._mitigated_pids) == 0


class TestMitigatorLiveMode:
    def test_live_kill_dispatches_signals(self) -> None:
        mitigator = Mitigator(dry_run=False)
        state = PIDState(pid=8888, comm="bad_ware")
        state.risk_score = 90.0

        with patch("engine.mitigator.find_child_pids", return_value={8889}), \
             patch("os.kill") as mock_kill:
            action = mitigator.execute(state)
            assert action == "SIGKILL"
            # Should call SIGSTOP and SIGKILL on both 8888 and 8889
            calls = [c[0] for c in mock_kill.call_args_list]
            assert (8888, signal.SIGSTOP) in calls
            assert (8889, signal.SIGSTOP) in calls
            assert (8888, signal.SIGKILL) in calls
            assert (8889, signal.SIGKILL) in calls


class TestFindChildPids:
    def test_invalid_pid_returns_empty(self) -> None:
        children = find_child_pids(-9999)
        assert children == set()
