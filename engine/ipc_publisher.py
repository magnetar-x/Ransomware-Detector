"""
engine/ipc_publisher.py – Telemetry broadcaster adhering strictly to common/ipc_schema.json.

Transports:
  1. Non-blocking UDP socket (127.0.0.1:51423 by default)
  2. Append-only JSONL log (/tmp/aegis_telemetry.jsonl by default)
  3. Optional Unix Domain Datagram Socket (/tmp/aegis_telemetry.sock)
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from typing import TYPE_CHECKING, Any

from engine.config import TELEMETRY_FILE, UDP_HOST, UDP_PORT

if TYPE_CHECKING:
    from engine.state_tracker import PIDState

logger = logging.getLogger(__name__)


class IPCPublisher:
    """
    Non-blocking telemetry broadcaster for alerts and periodic system metrics.
    """

    def __init__(
        self,
        udp_host: str = UDP_HOST,
        udp_port: int = UDP_PORT,
        log_path: str = TELEMETRY_FILE,
        uds_path: str | None = None,
    ) -> None:
        self.udp_host: str = udp_host
        self.udp_port: int = udp_port
        self.log_path: str = log_path
        self.uds_path: str | None = uds_path

        self._lock = threading.Lock()

        # Non-blocking UDP socket
        self._udp_sock: socket.socket | None = None
        try:
            self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_sock.setblocking(False)
        except OSError as exc:
            logger.warning("Could not create UDP telemetry socket: %s", exc)

        # Non-blocking UDS socket (optional)
        self._uds_sock: socket.socket | None = None
        if self.uds_path:
            try:
                self._uds_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                self._uds_sock.setblocking(False)
            except OSError as exc:
                logger.warning("Could not create UDS telemetry socket: %s", exc)

    def publish_alert(
        self,
        state: "PIDState",
        action_taken: str,
        system_metrics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build and broadcast an ALERT packet conforming strictly to common/ipc_schema.json.
        """
        payload: dict[str, Any] = {
            "timestamp": time.time(),
            "pid": state.pid,
            "process_name": state.comm or f"pid_{state.pid}",
            "threat_score": round(state.risk_score, 2),
            "action_taken": action_taken,
            "trigger_reasons": list(state.triggered_heuristics) if state.triggered_heuristics else ["HIGH_RISK_THRESHOLD_EXCEEDED"],
            "target_files_sample": list(state.target_files[-10:]),
        }
        if system_metrics is not None:
            payload["system_metrics"] = system_metrics

        self.emit(payload)
        return payload

    def publish_metric(
        self,
        system_metrics: dict[str, Any],
        tracked_pids_count: int = 0,
    ) -> dict[str, Any]:
        """
        Build and broadcast a periodic METRIC packet conforming to common/ipc_schema.json.
        """
        payload: dict[str, Any] = {
            "timestamp": time.time(),
            "pid": 0,
            "process_name": "aegis_engine",
            "threat_score": 0.0,
            "action_taken": "NONE",
            "trigger_reasons": [],
            "system_metrics": {
                **system_metrics,
                "active_tracked_pids": tracked_pids_count,
            },
        }
        self.emit(payload)
        return payload

    def emit(self, payload: dict[str, Any]) -> None:
        """
        Serialize payload to JSON and broadcast over configured transports.
        """
        try:
            line = json.dumps(payload) + "\n"
            encoded = line.encode("utf-8")
        except (TypeError, ValueError) as exc:
            logger.error("JSON serialization failed for IPC payload: %s", exc)
            return

        with self._lock:
            # 1. Append to log file
            try:
                log_dir = os.path.dirname(self.log_path)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as exc:
                logger.error("Failed writing to telemetry log %s: %s", self.log_path, exc)

            # 2. Non-blocking UDP broadcast
            if self._udp_sock is not None:
                try:
                    self._udp_sock.sendto(encoded, (self.udp_host, self.udp_port))
                except (BlockingIOError, OSError):
                    # Dashboard not listening or buffer full is normal in fire-and-forget
                    pass

            # 3. Non-blocking UDS broadcast (if configured)
            if self._uds_sock is not None and self.uds_path and os.path.exists(self.uds_path):
                try:
                    self._uds_sock.sendto(encoded, self.uds_path)
                except (BlockingIOError, OSError):
                    pass

    def close(self) -> None:
        """Close socket descriptors."""
        with self._lock:
            if self._udp_sock is not None:
                try:
                    self._udp_sock.close()
                except OSError:
                    pass
                self._udp_sock = None
            if self._uds_sock is not None:
                try:
                    self._uds_sock.close()
                except OSError:
                    pass
                self._uds_sock = None
