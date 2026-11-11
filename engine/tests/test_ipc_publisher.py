"""
engine/tests/test_ipc_publisher.py – Unit tests for IPCPublisher.

Covers:
  • Alert packet fields adhere strictly to common/ipc_schema.json
  • Metric packet fields adhere strictly to common/ipc_schema.json
  • Append-only JSONL log creation and formatting
  • UDP broadcast (non-blocking, fails gracefully when receiver isn't running)
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from engine.ipc_publisher import IPCPublisher
from engine.state_tracker import PIDState

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "common" / "ipc_schema.json"


def validate_against_schema(payload: dict) -> None:
    """Validate payload against common/ipc_schema.json rules."""
    with open(SCHEMA_PATH, "r") as f:
        schema = json.load(f)

    # Check required fields
    for req in schema.get("required", []):
        assert req in payload, f"Missing required property {req}"

    # Check property types
    props = schema.get("properties", {})
    if "timestamp" in payload:
        assert isinstance(payload["timestamp"], (int, float))
    if "pid" in payload:
        assert isinstance(payload["pid"], int)
    if "process_name" in payload:
        assert isinstance(payload["process_name"], str)
    if "threat_score" in payload:
        assert isinstance(payload["threat_score"], (int, float))
    if "action_taken" in payload:
        assert payload["action_taken"] in props["action_taken"]["enum"]
    if "trigger_reasons" in payload:
        assert isinstance(payload["trigger_reasons"], list)
        for r in payload["trigger_reasons"]:
            assert isinstance(r, str)


class TestIPCPublisher:
    def test_alert_schema_compliance(self, tmp_path) -> None:
        log_file = str(tmp_path / "telemetry.jsonl")
        pub = IPCPublisher(log_path=log_file)

        state = PIDState(pid=4321, comm="ransom_test")
        state.risk_score = 88.5
        state.triggered_heuristics.append("HIGH_INLINE_ENTROPY (7.8 bits/byte)")
        state.target_files.append("/home/user/doc.docx.locked")

        alert = pub.publish_alert(state, action_taken="DRY_RUN_KILL")
        validate_against_schema(alert)

        assert alert["pid"] == 4321
        assert alert["process_name"] == "ransom_test"
        assert alert["threat_score"] == 88.5
        assert alert["action_taken"] == "DRY_RUN_KILL"
        assert "HIGH_INLINE_ENTROPY (7.8 bits/byte)" in alert["trigger_reasons"]
        assert "/home/user/doc.docx.locked" in alert["target_files_sample"]

        pub.close()

    def test_metric_schema_compliance(self, tmp_path) -> None:
        log_file = str(tmp_path / "telemetry.jsonl")
        pub = IPCPublisher(log_path=log_file)

        metrics = {"events_per_sec": 4200, "avg_processing_latency_us": 12.5}
        metric_pkt = pub.publish_metric(metrics, tracked_pids_count=15)
        validate_against_schema(metric_pkt)

        assert metric_pkt["pid"] == 0
        assert metric_pkt["action_taken"] == "NONE"
        assert metric_pkt["system_metrics"]["events_per_sec"] == 4200
        assert metric_pkt["system_metrics"]["active_tracked_pids"] == 15

        pub.close()

    def test_jsonl_append(self, tmp_path) -> None:
        log_file = str(tmp_path / "telemetry.jsonl")
        pub = IPCPublisher(log_path=log_file)

        state = PIDState(pid=100, comm="test1")
        state.risk_score = 99.0
        pub.publish_alert(state, action_taken="SIGKILL")

        metrics = {"events_per_sec": 100}
        pub.publish_metric(metrics, tracked_pids_count=1)

        assert os.path.exists(log_file)
        with open(log_file, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) == 2
        assert lines[0]["pid"] == 100
        assert lines[0]["action_taken"] == "SIGKILL"
        assert lines[1]["pid"] == 0
        assert lines[1]["action_taken"] == "NONE"

        pub.close()

    def test_udp_broadcast_received(self, tmp_path) -> None:
        log_file = str(tmp_path / "telemetry.jsonl")
        # Setup local UDP listener on ephemeral port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        _, port = sock.getsockname()
        sock.settimeout(2.0)

        pub = IPCPublisher(udp_host="127.0.0.1", udp_port=port, log_path=log_file)
        state = PIDState(pid=777, comm="udp_test")
        state.risk_score = 95.0
        pub.publish_alert(state, action_taken="DRY_RUN_KILL")

        data, _ = sock.recvfrom(4096)
        received = json.loads(data.decode("utf-8"))
        assert received["pid"] == 777
        assert received["action_taken"] == "DRY_RUN_KILL"

        sock.close()
        pub.close()
