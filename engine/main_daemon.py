"""
engine/main_daemon.py – Main Daemon & Orchestration CLI.

Orchestrates the entire detection pipeline:
  • Event Ingestion (Live eBPF ringbuf or Mock synthetic streamer)
  • Canary honeyfile tripwires
  • Dual-stage Shannon entropy & magic byte tracking
  • Behavioral Sequence DAG detection
  • I/O velocity & extension mutation tracking
  • Two-stage process mitigation (Instant Freeze & Kill, or safe Dry-Run)
  • IPC Telemetry publication (UDP + JSONL conforming to common/ipc_schema.json)
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import Any

from engine.config import (
    DEFAULT_CANARY_DIR,
    EVENT_CLOSE,
    KILL_THRESHOLD,
    METRIC_INTERVAL_SEC,
    TELEMETRY_FILE,
    UDP_HOST,
    UDP_PORT,
    VERIFY_THRESHOLD,
)
from engine.heuristics.canary import CanaryManager
from engine.heuristics.entropy import check_disk_entropy, check_inline_entropy
from engine.heuristics.sequence_dag import check_sequence
from engine.ingestor import EventIngestor
from engine.ipc_publisher import IPCPublisher
from engine.mitigator import Mitigator
from engine.mock_streamer import AVAILABLE_SCENARIOS
from engine.state_tracker import StateTracker

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)
logger = logging.getLogger("aegis_engine")


class AegisEngineDaemon:
    """
    Core engine daemon coordinating ingestion, detection heuristics,
    mitigation, and telemetry.
    """

    def __init__(
        self,
        mode: str = "mock",
        scenario: str = "mixed",
        dry_run: bool = True,
        threshold: float = KILL_THRESHOLD,
        canary_dir: str = DEFAULT_CANARY_DIR,
        events_per_sec: int = 5000,
        udp_host: str = UDP_HOST,
        udp_port: int = UDP_PORT,
        log_path: str = TELEMETRY_FILE,
    ) -> None:
        self.mode = mode
        self.scenario = scenario
        self.dry_run = dry_run
        self.threshold = threshold
        self.canary_dir = canary_dir
        self.events_per_sec = events_per_sec

        self.state_tracker = StateTracker()
        self.canary_manager = CanaryManager(deploy_dir=self.canary_dir)
        self.mitigator = Mitigator(dry_run=self.dry_run)
        self.ipc_publisher = IPCPublisher(
            udp_host=udp_host, udp_port=udp_port, log_path=log_path
        )

        self._stop_event = threading.Event()
        self._total_events = 0
        self._total_latency_us = 0.0
        self._metrics_thread: threading.Thread | None = None
        self._ingestor: EventIngestor | None = None

    def process_event(self, event: dict[str, Any]) -> None:
        """
        Process a single canonical event through all detection heuristics.
        """
        t0 = time.perf_counter_ns()
        self._total_events += 1

        pid = event["pid"]
        comm = event.get("comm", "")
        uid = event.get("uid", 0)

        state = self.state_tracker.get_or_create(pid, comm=comm, uid=uid)
        self.state_tracker.record_event(state, event)

        # 1. Canary Tripwire (Zero-Tolerance)
        canary_score = self.canary_manager.check_event(event, state)
        if canary_score > 0:
            self.state_tracker.add_score(state, canary_score)

        # 2. Stage 1: Inline Entropy & Magic Overwrites
        entropy_score = check_inline_entropy(event, state)
        if entropy_score > 0:
            self.state_tracker.add_score(state, entropy_score)

        # 3. Behavioral Sequence DAG (In-Place or Copy-and-Shred)
        dag_score = check_sequence(event, state)
        if dag_score > 0:
            self.state_tracker.add_score(state, dag_score)

        # 4. Rapid Rename Mutation Uniformity
        ext_score = self.state_tracker.check_extension_uniformity(state, event)
        if ext_score > 0:
            self.state_tracker.add_score(state, ext_score)
            state.triggered_heuristics.append("RAPID_RENAME_BURST")

        # 5. Stage 2: On-Disk Entropy Check on CLOSE if score is already elevated
        if state.risk_score >= VERIFY_THRESHOLD and event.get("event_type") == EVENT_CLOSE:
            filename = event.get("filename", "")
            if filename:
                disk_score = check_disk_entropy(filename, state)
                if disk_score > 0:
                    self.state_tracker.add_score(state, disk_score)

        # 6. Check Threat Threshold & Mitigate
        if state.risk_score >= self.threshold:
            action = self.mitigator.execute(state)
            if action in ("SIGKILL", "DRY_RUN_KILL"):
                # Compute instantaneous latency metrics for the alert
                t_end = time.perf_counter_ns()
                latency_us = (t_end - t0) / 1000.0
                sys_metrics = {
                    "events_processed": self._total_events,
                    "active_tracked_pids": self.state_tracker.active_pid_count,
                    "avg_processing_latency_us": round(latency_us, 2),
                }
                self.ipc_publisher.publish_alert(
                    state, action_taken=action, system_metrics=sys_metrics
                )

        t_end = time.perf_counter_ns()
        self._total_latency_us += (t_end - t0) / 1000.0

    def _run_metrics_loop(self) -> None:
        """Periodic background worker for publishing telemetry metrics & cleanup."""
        last_count = 0
        last_time = time.monotonic()

        while not self._stop_event.is_set():
            time.sleep(METRIC_INTERVAL_SEC)
            now = time.monotonic()
            elapsed = now - last_time
            if elapsed <= 0:
                continue

            current_events = self._total_events
            eps = int((current_events - last_count) / elapsed)
            last_count = current_events
            last_time = now

            avg_latency = (
                (self._total_latency_us / current_events)
                if current_events > 0
                else 0.0
            )

            metrics = {
                "events_per_sec": eps,
                "total_events": current_events,
                "avg_processing_latency_us": round(avg_latency, 2),
            }
            self.ipc_publisher.publish_metric(
                metrics, tracked_pids_count=self.state_tracker.active_pid_count
            )
            # Evict stale PIDs
            self.state_tracker.cleanup_stale(max_age_sec=30.0)

    def start(self) -> None:
        """Start the engine daemon."""
        logger.info("Initializing AegisBPF Engine (mode=%s, dry_run=%s)", self.mode, self.dry_run)
        self.canary_manager.deploy()

        self._metrics_thread = threading.Thread(target=self._run_metrics_loop, daemon=True)
        self._metrics_thread.start()

        canary_paths = list(self.canary_manager.canary_paths)
        self._ingestor = EventIngestor(
            mode=self.mode,
            callback=self.process_event,
            mock_scenario=self.scenario,
            mock_eps=self.events_per_sec,
            canary_paths=canary_paths,
        )

        logger.info("AegisBPF Engine is now processing events...")
        try:
            self._ingestor.start()
        except KeyboardInterrupt:
            logger.info("Shutdown requested via KeyboardInterrupt")
        finally:
            self.stop()

    def stop(self) -> None:
        """Graceful shutdown and resource cleanup."""
        if self._stop_event.is_set():
            return
        logger.info("Stopping AegisBPF Engine...")
        self._stop_event.set()

        if self._ingestor is not None:
            self._ingestor.stop()

        if self._metrics_thread is not None and self._metrics_thread.is_alive():
            self._metrics_thread.join(timeout=1.0)

        self.canary_manager.cleanup()
        self.ipc_publisher.close()
        logger.info("AegisBPF Engine stopped.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AegisBPF User-Space Detection Engine")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--mock", action="store_true", default=True, help="Run in mock streaming mode (default)")
    mode_group.add_argument("--live", action="store_true", help="Run in live eBPF ringbuf mode")

    parser.add_argument("--scenario", choices=AVAILABLE_SCENARIOS, default="mixed", help="Mock scenario to simulate")
    parser.add_argument("--dry-run", "--safe-mode", action="store_true", default=True, dest="dry_run", help="Log mitigation without killing processes (default)")
    parser.add_argument("--live-mitigation", action="store_false", dest="dry_run", help="Enable actual SIGSTOP/SIGKILL delivery")
    parser.add_argument("--threshold", type=float, default=KILL_THRESHOLD, help="Threat score threshold for mitigation (default 75.0)")
    parser.add_argument("--canary-dir", type=str, default=DEFAULT_CANARY_DIR, help="Canary honeyfile deployment directory")
    parser.add_argument("--events-per-sec", type=int, default=5000, help="Mock event throughput")
    parser.add_argument("--udp-port", type=int, default=UDP_PORT, help="UDP telemetry port")
    parser.add_argument("--log-file", type=str, default=TELEMETRY_FILE, help="Telemetry JSONL log path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    mode = "live" if args.live else "mock"
    daemon = AegisEngineDaemon(
        mode=mode,
        scenario=args.scenario,
        dry_run=args.dry_run,
        threshold=args.threshold,
        canary_dir=args.canary_dir,
        events_per_sec=args.events_per_sec,
        udp_port=args.udp_port,
        log_path=args.log_file,
    )

    def _sig_handler(sig, frame):  # noqa: ARG001
        logger.info("Received signal %d, exiting...", sig)
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    daemon.start()


if __name__ == "__main__":
    main()
