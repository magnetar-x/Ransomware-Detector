"""
engine/tests/conftest.py – Shared fixtures for the engine test suite.

Every test that touches the engine pipeline uses ``--dry-run`` mode
unconditionally (see ``dry_run`` fixture).
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from typing import Generator

import pytest

from engine.config import DEFAULT_CANARY_DIR


# ---------------------------------------------------------------------------
# Global safety: dry-run is always True in the test suite
# ---------------------------------------------------------------------------

@pytest.fixture
def dry_run() -> bool:
    """Mitigation dry-run flag – always True in tests."""
    return True


# ---------------------------------------------------------------------------
# Temporary canary directory
# ---------------------------------------------------------------------------

@pytest.fixture
def canary_dir(tmp_path) -> str:
    """Return a per-test temporary canary directory path."""
    d = str(tmp_path / "canary_zone")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Event collector helper
# ---------------------------------------------------------------------------

class EventCollector:
    """Thread-safe list that collects event dicts from a callback."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def __call__(self, event: dict) -> None:
        with self._lock:
            self.events.append(event)

    def __len__(self) -> int:
        with self._lock:
            return len(self.events)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self.events)


@pytest.fixture
def collector() -> EventCollector:
    """Return a fresh EventCollector."""
    return EventCollector()
