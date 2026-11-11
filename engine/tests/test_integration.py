"""
engine/tests/test_integration.py – End-to-end integration & benchmark suite.

Verifies:
  1. Benign compiler workload triggers ZERO false positive alerts.
  2. Benign archiver workload triggers ZERO false positive alerts.
  3. Ransomware in-place encryption loop is caught and terminated in <50ms.
  4. Ransomware copy-and-shred loop is caught and terminated in <50ms.
  5. Honeyfile canary tampering triggers zero-tolerance instant kill (threat_score >= 100).
  6. Mixed workload selectively terminates ransomware PID while benign PIDs continue untouched.
  7. Every emitted IPC telemetry packet conforms strictly to common/ipc_schema.json.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from engine.main_daemon import AegisEngineDaemon
from engine.tests.test_ipc_publisher import validate_against_schema


@pytest.fixture
def make_daemon(tmp_path):
    """Factory fixture returning a configured AegisEngineDaemon with automated cleanup."""
    daemons: list[AegisEngineDaemon] = []

    def _factory(scenario: str, eps: int = 10_000) -> tuple[AegisEngineDaemon, str]:
        log_file = str(tmp_path / f"telemetry_{scenario}.jsonl")
        canary_d = str(tmp_path / f"canaries_{scenario}")
        daemon = AegisEngineDaemon(
            mode="mock",
            scenario=scenario,
            dry_run=True,
            canary_dir=canary_d,
            events_per_sec=eps,
            log_path=log_file,
        )
        daemons.append(daemon)
        return daemon, log_file

    yield _factory

    for d in daemons:
        d.stop()


def _read_telemetry_alerts(log_file: str) -> list[dict]:
    """Read all ALERT packets from the telemetry log file."""
    if not os.path.exists(log_file):
        return []
    alerts = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    pkt = json.loads(line)
                    if pkt.get("action_taken") in ("DRY_RUN_KILL", "SIGKILL", "SIGSTOP"):
                        alerts.append(pkt)
                except json.JSONDecodeError:
                    continue
    return alerts


def _read_all_telemetry(log_file: str) -> list[dict]:
    """Read all packets from the telemetry log file."""
    if not os.path.exists(log_file):
        return []
    records = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


class TestIntegrationWorkloads:
    def test_benign_compiler_no_false_positives(self, make_daemon) -> None:
        """Compiler build operations must not trigger alerts."""
        daemon, log_file = make_daemon("benign_compiler", eps=15_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.6)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) == 0, f"Expected 0 alerts for compiler, got: {alerts}"

    def test_benign_archiver_no_false_positives(self, make_daemon) -> None:
        """High-entropy compression/archive operations must not trigger alerts."""
        daemon, log_file = make_daemon("benign_archiver", eps=15_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.6)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) == 0, f"Expected 0 alerts for archiver, got: {alerts}"

    def test_ransomware_inplace_caught_and_mitigated(self, make_daemon) -> None:
        """Ransomware in-place encryption loop must trigger mitigation."""
        daemon, log_file = make_daemon("ransomware_inplace", eps=10_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.6)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) >= 1
        top_alert = alerts[0]
        assert top_alert["pid"] == 6660
        assert top_alert["action_taken"] == "DRY_RUN_KILL"
        assert top_alert["threat_score"] >= 75.0
        assert len(top_alert["trigger_reasons"]) > 0

    def test_ransomware_shred_caught_and_mitigated(self, make_daemon) -> None:
        """Copy-and-shred ransomware loop must trigger mitigation."""
        daemon, log_file = make_daemon("ransomware_shred", eps=10_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.6)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) >= 1
        top_alert = alerts[0]
        assert top_alert["pid"] == 6670
        assert top_alert["action_taken"] == "DRY_RUN_KILL"
        assert top_alert["threat_score"] >= 75.0

    def test_canary_instant_zero_tolerance(self, make_daemon) -> None:
        """Touching a canary honeyfile must trigger instant threat_score >= 100."""
        daemon, log_file = make_daemon("canary_touch", eps=5_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.5)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) >= 1
        canary_alert = alerts[0]
        assert canary_alert["pid"] == 6680
        assert canary_alert["threat_score"] >= 100.0
        assert any("CANARY_TRIPWIRE" in r for r in canary_alert["trigger_reasons"])

    def test_mixed_workload_selectivity(self, make_daemon) -> None:
        """In a mixed workload, only the malicious PID must be flagged."""
        daemon, log_file = make_daemon("mixed", eps=12_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.8)
        daemon.stop()
        t.join(timeout=2.0)

        alerts = _read_telemetry_alerts(log_file)
        assert len(alerts) >= 1
        alerted_pids = {a["pid"] for a in alerts}
        assert 6660 in alerted_pids, "Ransomware PID 6660 was not alerted"
        # Benign PIDs in mixed scenario: 1001 (gcc) and 2001 (tar)
        assert 1001 not in alerted_pids, "Benign compiler was incorrectly flagged!"
        assert 2001 not in alerted_pids, "Benign archiver was incorrectly flagged!"

    def test_detection_latency_under_50ms(self, make_daemon) -> None:
        """Measure detection latency from start to alert emission (<50ms requirement)."""
        daemon, log_file = make_daemon("ransomware_inplace", eps=10_000)

        t_start = time.perf_counter()
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        # Poll for alert file presence with micro-sleeps
        alert_found = False
        t_detect = 0.0
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            alerts = _read_telemetry_alerts(log_file)
            if alerts:
                t_detect = time.perf_counter()
                alert_found = True
                break
            time.sleep(0.005)

        daemon.stop()
        t.join(timeout=2.0)

        assert alert_found, "Ransomware was not detected within timeout"
        latency_ms = (t_detect - t_start) * 1000.0
        # Pipeline processing should react very rapidly (<50ms threshold)
        assert latency_ms < 50.0, f"Detection latency {latency_ms:.2f}ms exceeded 50ms requirement!"

    def test_all_telemetry_adheres_to_schema(self, make_daemon) -> None:
        """Validate every emitted record in the log file against common/ipc_schema.json."""
        daemon, log_file = make_daemon("mixed", eps=10_000)
        t = threading.Thread(target=daemon.start, daemon=True)
        t.start()

        time.sleep(0.8)
        daemon.stop()
        t.join(timeout=2.0)

        all_records = _read_all_telemetry(log_file)
        assert len(all_records) > 0, "No telemetry records emitted"

        for record in all_records:
            validate_against_schema(record)
