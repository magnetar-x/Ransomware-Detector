"""
engine/heuristics/entropy.py – Dual-stage Shannon entropy analyser.

Stage 1 (Inline — per EVENT_WRITE):
    Compute H(X) on the 64-byte ``payload_sample`` using a precomputed
    log₂ lookup table → O(256) per call (effectively constant).
    If the file had a known magic header on OPEN and this WRITE
    overwrites it with high-entropy data (H > 5.4), add +35 to score.

Stage 2 (On-Disk — per EVENT_CLOSE when score ≥ 40):
    Read the first 4096 bytes from the closed file, compute full
    8-bit entropy.  If H > 7.6 and the extension is not in the
    archive/media whitelist, add +30 to score.
"""

from __future__ import annotations

import logging
import math
import os
from typing import TYPE_CHECKING

from engine.config import (
    ENTROPY_DISK_HIGH,
    ENTROPY_INLINE_HIGH,
    EVENT_OPEN,
    EVENT_WRITE,
    HIGH_ENTROPY_EXTENSIONS,
    MAGIC_BYTES,
    PAYLOAD_SAMPLE_SIZE,
    SCORE_DISK_ENTROPY,
    SCORE_MAGIC_OVERWRITE,
)

if TYPE_CHECKING:
    from engine.state_tracker import PIDState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Precomputed log₂ lookup table
# ---------------------------------------------------------------------------
# Entropy is evaluated using a lookup table for log2(count).  This avoids
# calling math.log2 once per histogram bucket while retaining support for both
# the 64-byte inline sample and the 4096-byte disk sample.
_MAX_LOOKUP_COUNT = 4096
_LOG2_COUNTS = [0.0] * (_MAX_LOOKUP_COUNT + 1)
for _count in range(1, _MAX_LOOKUP_COUNT + 1):
    _LOG2_COUNTS[_count] = math.log2(_count)

def shannon_entropy(data: bytes) -> float:
    r"""
    Compute Shannon entropy H(X) in **bits per byte**.

    .. math::
        H(X) = -\sum_{i=0}^{255} P(x_i)\,\log_2 P(x_i)

    Returns 0.0 for empty input.
    """
    length = len(data)
    if length == 0:
        return 0.0

    # Count byte-value frequencies  (O(N))
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    # Compute entropy  (O(256) — constant)
    log_n = math.log2(length)
    entropy = log_n
    for c in counts:
        if c > 0:
            log_c = _LOG2_COUNTS[c] if c <= _MAX_LOOKUP_COUNT else math.log2(c)
            entropy -= (c / length) * log_c
    return entropy


# ---------------------------------------------------------------------------
# Magic-byte helpers
# ---------------------------------------------------------------------------

def _match_magic(header: bytes) -> str | None:
    """Return the format label if *header* starts with a known magic, else None."""
    for magic, label in MAGIC_BYTES.items():
        if header[: len(magic)] == magic:
            return label
    return None


def _try_read_magic_from_disk(filepath: str) -> bytes | None:
    """Try to read the first 4 bytes of *filepath*.  Returns None on failure."""
    try:
        with open(filepath, "rb") as fh:
            data = fh.read(4)
            return data if len(data) >= 4 else None
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Stage 1 — Inline entropy check  (called on every event)
# ---------------------------------------------------------------------------

def check_inline_entropy(event: dict, state: "PIDState") -> float:
    """
    Process an event through Stage-1 entropy analysis.

    • On EVENT_OPEN: stash the file's magic bytes (from ``payload_sample``
      if available, otherwise attempt an on-disk read).
    • On EVENT_WRITE: compute Shannon entropy on the 64-byte payload
      sample.  If the file previously had a known magic header and the
      write is high-entropy (H > 5.4), return +35.0 score delta.

    Side-effect: always updates ``state.last_write_entropy``.

    Returns
    -------
    float
        Score delta to add to the PID (0.0, or +35.0 on magic overwrite).
    """
    event_type = event.get("event_type")
    filename = event.get("filename", "")

    # ── OPEN: cache magic bytes ──────────────────────────────────────────
    if event_type == EVENT_OPEN and filename:
        payload = event.get("payload_sample", b"")
        if payload and len(payload) >= 4:
            # Mock mode: magic bytes are embedded in the OPEN payload
            magic_header = payload[:4]
        else:
            # Live mode: try to read from disk
            magic_header = _try_read_magic_from_disk(filename)

        if magic_header and _match_magic(magic_header):
            state.magic_bytes[filename] = magic_header
        return 0.0

    # ── WRITE: compute inline entropy ────────────────────────────────────
    if event_type == EVENT_WRITE:
        payload = event.get("payload_sample", b"")
        if not payload:
            state.last_write_entropy = 0.0
            return 0.0

        h = shannon_entropy(payload)
        state.last_write_entropy = h

        write_offset = int(event.get("offset", 0))
        if write_offset == 0 and h > ENTROPY_INLINE_HIGH and filename in state.magic_bytes:
            cached_magic = state.magic_bytes[filename]
            if _match_magic(cached_magic):
                label = _match_magic(cached_magic)
                logger.debug(
                    "Magic-overwrite detected  pid=%d  file=%s  "
                    "format=%s  H=%.2f",
                    state.pid, filename, label, h,
                )
                state.triggered_heuristics.append(
                    f"HIGH_INLINE_ENTROPY ({h:.2f} bits/byte)"
                )
                # Consumed — remove from cache
                del state.magic_bytes[filename]
                return SCORE_MAGIC_OVERWRITE

        return 0.0

    return 0.0


# ---------------------------------------------------------------------------
# Stage 2 — On-disk entropy check  (called on EVENT_CLOSE when score ≥ 40)
# ---------------------------------------------------------------------------

def check_disk_entropy(filepath: str, state: "PIDState") -> float:
    """
    Read the first 4096 bytes of *filepath* from disk and compute full
    8-bit Shannon entropy.

    Returns +30.0 if H > 7.6 **and** the extension is not in the
    archive/media whitelist; 0.0 otherwise.

    Gracefully returns 0.0 if the file cannot be read.
    """
    _, ext = os.path.splitext(filepath)
    if ext.lower() in HIGH_ENTROPY_EXTENSIONS:
        return 0.0

    try:
        with open(filepath, "rb") as fh:
            data = fh.read(4096)
    except (OSError, PermissionError):
        return 0.0

    if len(data) < 64:
        # Too small for meaningful entropy measurement
        return 0.0

    h = shannon_entropy(data)
    if h > ENTROPY_DISK_HIGH:
        logger.debug(
            "Disk entropy elevated  pid=%d  file=%s  H=%.2f",
            state.pid, filepath, h,
        )
        state.triggered_heuristics.append(
            f"HIGH_DISK_ENTROPY ({h:.2f} bits/byte)"
        )
        return SCORE_DISK_ENTROPY

    return 0.0
