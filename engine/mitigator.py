"""
engine/mitigator.py – Process tree suspension and termination.

Implements two-stage surgical mitigation:
  • Stage 1 (Instant Freeze): Send SIGSTOP to the target PID and its child process tree.
  • Stage 2 (Terminate): Verify PID is not whitelisted, dispatch SIGKILL.

Safe Mitigation Testing:
  When ``dry_run=True`` (via --dry-run or in tests), no actual signals are sent.
  Instead, the action is logged and "DRY_RUN_KILL" is returned to be emitted
  via IPC without killing real host processes.
"""

from __future__ import annotations

import logging
import os
import signal
from typing import TYPE_CHECKING, Iterable

from engine.config import OS_CRITICAL_WHITELIST

if TYPE_CHECKING:
    from engine.state_tracker import PIDState

logger = logging.getLogger(__name__)


def find_child_pids(parent_pid: int) -> set[int]:
    """
    Discover all descendant process IDs of parent_pid by walking /proc.
    Returns an empty set if parent_pid is invalid or dead.
    """
    children: set[int] = set()
    task_dir = f"/proc/{parent_pid}/task"
    if not os.path.isdir(task_dir):
        return children

    try:
        tids = os.listdir(task_dir)
    except (OSError, PermissionError):
        return children

    for tid in tids:
        children_file = f"{task_dir}/{tid}/children"
        try:
            with open(children_file, "r") as f:
                content = f.read().strip()
                if content:
                    for c_str in content.split():
                        c_pid = int(c_str)
                        if c_pid not in children:
                            children.add(c_pid)
                            # Recursively find grandchildren
                            children.update(find_child_pids(c_pid))
        except (OSError, PermissionError, ValueError):
            continue

    return children


class Mitigator:
    """
    Process mitigation handler supporting live SIGSTOP/SIGKILL cascades and
    safe --dry-run emulation.
    """

    def __init__(
        self,
        dry_run: bool = False,
        whitelist: Iterable[str] = OS_CRITICAL_WHITELIST,
    ) -> None:
        self.dry_run: bool = dry_run
        self.whitelist: frozenset[str] = frozenset(whitelist)
        self._mitigated_pids: set[int] = set()

    def is_whitelisted(self, comm: str) -> bool:
        """Check if command name is an essential OS binary."""
        base_comm = os.path.basename(comm).strip()
        return base_comm in self.whitelist

    def execute(self, state: "PIDState") -> str:
        """
        Execute mitigation against the offending process in state.

        Returns
        -------
        str
            Action taken: "NONE", "SIGSTOP", "SIGKILL", or "DRY_RUN_KILL".
            Conforms strictly to common/ipc_schema.json enum.
        """
        pid = state.pid
        comm = state.comm

        # Check critical system whitelist
        if self.is_whitelisted(comm):
            logger.warning(
                "PID %d (%s) breached threshold (score=%.1f) but is WHITELISTED. Skipping mitigation.",
                pid, comm, state.risk_score,
            )
            return "NONE"

        # Check if already mitigated to prevent signal storms
        if pid in self._mitigated_pids:
            return "DRY_RUN_KILL" if self.dry_run else "SIGKILL"

        self._mitigated_pids.add(pid)

        if self.dry_run:
            logger.info(
                "[DRY_RUN_KILL] Simulated mitigation for PID %d (%s) score=%.1f. No signal dispatched.",
                pid, comm, state.risk_score,
            )
            return "DRY_RUN_KILL"

        # Live mitigation: Stage 1 (SIGSTOP) -> Stage 2 (SIGKILL)
        logger.warning(
            "Executing live mitigation on PID %d (%s) [Score=%.1f]",
            pid, comm, state.risk_score,
        )

        tree = find_child_pids(pid)
        tree.add(pid)

        # Stage 1: Freeze tree
        for target_pid in tree:
            try:
                os.kill(target_pid, signal.SIGSTOP)
            except (ProcessLookupError, PermissionError) as exc:
                logger.debug("SIGSTOP on PID %d failed: %s", target_pid, exc)

        # Stage 2: Terminate tree
        for target_pid in tree:
            try:
                os.kill(target_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as exc:
                logger.debug("SIGKILL on PID %d failed: %s", target_pid, exc)

        return "SIGKILL"

    def reset(self) -> None:
        """Clear list of mitigated PIDs."""
        self._mitigated_pids.clear()
