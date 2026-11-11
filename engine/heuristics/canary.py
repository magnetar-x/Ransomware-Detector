"""
engine/heuristics/canary.py – Automated honeyfile deployment & tripwires.

On daemon startup, ``CanaryManager.deploy()`` creates hidden decoy files
in a configurable directory.  Each decoy has a realistic low-entropy
header that mimics a real document/database.

**Zero-Tolerance Rule:**  Any process that issues EVENT_WRITE,
EVENT_RENAME, or EVENT_UNLINK against a canary path receives an
instant +100.0 score, guaranteeing immediate mitigation.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import TYPE_CHECKING

from engine.config import (
    CANARY_SCORE_INSTANT,
    DEFAULT_CANARY_DIR,
    EVENT_RENAME,
    EVENT_UNLINK,
    EVENT_WRITE,
)

if TYPE_CHECKING:
    from engine.state_tracker import PIDState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Decoy file definitions
# ---------------------------------------------------------------------------
# (filename, header_bytes)
# Each header mimics a real file format at low entropy so normal
# filesystem scans don't flag them, but any *modification* is instant-kill.

_DECOY_SPECS: list[tuple[str, bytes]] = [
    (
        ".~lock_financial_backup.xlsx",
        # OOXML / ZIP magic + plausible XML content
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        + b"<workbook><sheet name=\"Q4 Revenue\"/></workbook>"
        + b"\x00" * 128,
    ),
    (
        "00_passwords_vault.kdbx",
        # KeePass 2.x magic signature
        b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"
        + b"\x01\x00\x03\x00"
        + b"KeePass encrypted database v4\n"
        + b"\x00" * 128,
    ),
    (
        "_recovery_keys.docx",
        # OOXML / ZIP magic
        b"PK\x03\x04\x14\x00\x00\x00\x08\x00"
        + b"<?xml version=\"1.0\"?>\n"
        + b"<document><body>Recovery Key: XXXX-XXXX</body></document>"
        + b"\x00" * 64,
    ),
    (
        ".budget_2026_FINAL.pdf",
        # PDF magic
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        + b"Lorem ipsum dolor sit amet, consectetur adipiscing.\n"
        + b"\x00" * 64,
    ),
]


class CanaryManager:
    """
    Manages honeyfile deployment and O(1) path-lookup for tripwire checks.

    Parameters
    ----------
    deploy_dir : str
        Absolute path of the directory where decoy files are created.
    """

    def __init__(self, deploy_dir: str = DEFAULT_CANARY_DIR) -> None:
        self._deploy_dir: str = deploy_dir
        self._canary_paths: set[str] = set()
        self._deployed: bool = False

    # -- public API ---------------------------------------------------------

    def deploy(self) -> None:
        """Create decoy files on disk and register their absolute paths."""
        os.makedirs(self._deploy_dir, exist_ok=True)
        for filename, content in _DECOY_SPECS:
            path = os.path.join(self._deploy_dir, filename)
            try:
                with open(path, "wb") as fh:
                    fh.write(content)
                self._canary_paths.add(os.path.abspath(path))
                logger.info("Canary deployed: %s", path)
            except OSError as exc:
                logger.warning("Failed to deploy canary %s: %s", path, exc)
        self._deployed = True

    def is_canary(self, filepath: str) -> bool:
        """O(1) check whether *filepath* is a deployed honeyfile."""
        return os.path.abspath(filepath) in self._canary_paths

    @property
    def canary_paths(self) -> frozenset[str]:
        """Return an immutable snapshot of all deployed canary paths."""
        return frozenset(self._canary_paths)

    def check_event(self, event: dict, state: "PIDState | None" = None) -> float:
        """
        Check an event against deployed canaries.

        Returns +100.0 if the event targets a canary file via WRITE,
        RENAME, or UNLINK; 0.0 otherwise.
        """
        event_type = event.get("event_type")
        if event_type not in (EVENT_WRITE, EVENT_RENAME, EVENT_UNLINK):
            return 0.0

        filename = event.get("filename", "")
        new_filename = event.get("new_filename", "")

        triggered = False
        if filename and self.is_canary(filename):
            triggered = True
        if new_filename and self.is_canary(new_filename):
            triggered = True

        if triggered:
            logger.critical(
                "CANARY TRIPWIRE  pid=%s  comm=%s  file=%s  event=%d",
                event.get("pid"), event.get("comm"), filename, event_type,
            )
            if state is not None:
                state.triggered_heuristics.append(
                    f"CANARY_TRIPWIRE ({filename})"
                )
            return CANARY_SCORE_INSTANT

        return 0.0

    def cleanup(self) -> None:
        """Remove deployed canary files and directory."""
        if self._deployed and os.path.isdir(self._deploy_dir):
            try:
                shutil.rmtree(self._deploy_dir)
                logger.info("Canary directory removed: %s", self._deploy_dir)
            except OSError as exc:
                logger.warning(
                    "Failed to clean canary dir %s: %s",
                    self._deploy_dir, exc,
                )
        self._canary_paths.clear()
        self._deployed = False
